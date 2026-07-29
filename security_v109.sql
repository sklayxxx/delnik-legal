-- Дельник: защита откликов и решений работодателя (шаг 2).
-- Запуск: docker exec -i supabase-db psql -U postgres -d postgres < /root/security_v109.sql
--
-- Логика: право UPDATE на чужую заявку остаётся (без него не работают
-- отклики и этапы), но триггер НЕ бросает ошибку, а молча возвращает
-- защищённые поля к серверным значениям. Поэтому устаревшая копия у
-- клиента не приводит к откату записи (тот самый баг с отменой отклика).

begin;

do $do$
declare
  dtype text;
begin
  select atttypid::regtype::text into dtype
  from pg_attribute
  where attrelid = 'public.shared_jobs'::regclass
    and attname = 'data'
    and attnum > 0;

  if dtype is null then
    raise exception 'column shared_jobs.data not found';
  end if;

  execute format($body$
create or replace function public.guard_shared_jobs_update()
returns trigger
language plpgsql
security definer
set search_path = public
as $fn$
declare
  o jsonb := to_jsonb(old.data);
  n jsonb := to_jsonb(new.data);
  caller text := (auth.uid())::text;
  owner_id text;
  k text;
  apps jsonb;
  views jsonb;
begin
  -- Обслуживание через psql (нет пользовательской сессии) не ограничиваем.
  if caller is null then
    return new;
  end if;

  owner_id := o ->> 'employerId';

  -- Автор заявки: запрещаем только передачу заявки другому владельцу.
  if caller = owner_id then
    if (n ->> 'employerId') is distinct from owner_id then
      raise exception 'employerId change is not allowed';
    end if;
    return new;
  end if;

  -- Не автор: содержание объявления и решения работодателя
  -- всегда берём из старой строки.
  for k in
    select unnest(array[
      'employerId', 'employerName', 'title', 'description', 'address',
      'city', 'lat', 'lng', 'category', 'photos', 'isUrgent', 'isFixedPay',
      'payPerHour', 'workersNeeded', 'date', 'createdAt',
      'rejectedApplicants', 'employerDone'
    ])
  loop
    if o ? k then
      n := jsonb_set(n, array[k], o -> k, true);
    else
      n := n - k;
    end if;
  end loop;

  -- Список откликнувшихся: берём серверный и меняем только СЕБЯ.
  apps := coalesce(o -> 'applicants', '[]'::jsonb);
  if exists (
    select 1 from jsonb_array_elements_text(
      coalesce(n -> 'applicants', '[]'::jsonb)) e where e = caller
  ) then
    if not exists (
      select 1 from jsonb_array_elements_text(apps) e where e = caller
    ) then
      apps := apps || to_jsonb(caller);
    end if;
  else
    apps := coalesce((
      select jsonb_agg(e) from jsonb_array_elements_text(apps) e
      where e <> caller
    ), '[]'::jsonb);
  end if;
  n := jsonb_set(n, array['applicants'], apps, true);

  -- Просмотры: только добавить себя, чужие удалить нельзя.
  views := coalesce(o -> 'viewedBy', '[]'::jsonb);
  if exists (
    select 1 from jsonb_array_elements_text(
      coalesce(n -> 'viewedBy', '[]'::jsonb)) e where e = caller
  ) and not exists (
    select 1 from jsonb_array_elements_text(views) e where e = caller
  ) then
    views := views || to_jsonb(caller);
  end if;
  n := jsonb_set(n, array['viewedBy'], views, true);

  new.data := n::text::%s;
  return new;
end;
$fn$;
  $body$, dtype);
end
$do$;

drop trigger if exists trg_guard_shared_jobs on public.shared_jobs;
create trigger trg_guard_shared_jobs
  before update on public.shared_jobs
  for each row execute function public.guard_shared_jobs_update();

commit;

select tgname, tgenabled from pg_trigger
where tgrelid = 'public.shared_jobs'::regclass and not tgisinternal;

select prosecdef as security_definer, pg_get_function_identity_arguments(oid) as args
from pg_proc where proname = 'guard_shared_jobs_update';
