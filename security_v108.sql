-- Дельник: серверная защита v1.0.8
-- Запуск: docker exec -i supabase-db psql -U postgres -d postgres < /root/security_v108.sql

begin;

-- 1. Дубли политик на отзывах: слабые перекрывали строгие,
--    из-за этого можно было писать отзывы самому себе.
drop policy if exists reviews_insert_own on public.reviews;
drop policy if exists reviews_update_own on public.reviews;

-- 2. Список модераторов. Пополняется только вручную через psql.
create table if not exists public.moderators (
  uid text primary key,
  note text not null default '',
  created_at timestamptz not null default now()
);

alter table public.moderators enable row level security;

drop policy if exists moderators_read_self on public.moderators;
create policy moderators_read_self on public.moderators
  for select to authenticated
  using (uid = (auth.uid())::text);

-- 3. Блокировки. Читать может любой вошедший, писать — только модератор.
--    Поэтому забаненный не может снять бан с себя.
create table if not exists public.bans (
  user_id text primary key,
  banned_until timestamptz not null,
  reason text not null default '',
  created_at timestamptz not null default now()
);

alter table public.bans enable row level security;

drop policy if exists bans_read on public.bans;
create policy bans_read on public.bans
  for select to authenticated
  using (true);

drop policy if exists bans_write_moderator on public.bans;
create policy bans_write_moderator on public.bans
  for all to authenticated
  using (exists (select 1 from public.moderators m
                 where m.uid = (auth.uid())::text))
  with check (exists (select 1 from public.moderators m
                      where m.uid = (auth.uid())::text));

create or replace function public.is_banned(p_uid text)
returns boolean
language sql
stable
security definer
set search_path = public
as $fn$
  select exists (
    select 1 from public.bans b
    where b.user_id = p_uid and b.banned_until > now()
  );
$fn$;

-- 4. Забаненный не может создавать заявки, писать в чат и отзывы.
drop policy if exists shared_jobs_insert_own on public.shared_jobs;
create policy shared_jobs_insert_own on public.shared_jobs
  for insert to authenticated
  with check (
    (data ->> 'employerId') = (auth.uid())::text
    and not public.is_banned((auth.uid())::text)
  );

drop policy if exists messages_insert_own on public.messages;
create policy messages_insert_own on public.messages
  for insert to authenticated
  with check (
    sender_id = (auth.uid())::text
    and not public.is_banned((auth.uid())::text)
  );

drop policy if exists reviews_insert on public.reviews;
create policy reviews_insert on public.reviews
  for insert to authenticated
  with check (
    author_id = (auth.uid())::text
    and author_id <> target_id
    and not public.is_banned((auth.uid())::text)
  );

-- 5. Защита содержания заявок.
--    Право UPDATE у всех нужно для откликов (список откликнувшихся
--    хранится внутри строки заявки), поэтому само объявление
--    защищаем триггером. Список полей совпадает с тем, что приложение
--    и так берёт с сервера, поэтому отклики и этапы работы не страдают.
create or replace function public.guard_shared_jobs_update()
returns trigger
language plpgsql
security definer
set search_path = public
as $fn$
declare
  k text;
  caller text;
begin
  caller := (auth.uid())::text;

  -- Обслуживание через psql (без пользовательской сессии) не ограничиваем.
  if caller is null then
    return new;
  end if;

  -- Автор заявки: запрещаем только передачу заявки другому владельцу.
  if caller = (old.data ->> 'employerId') then
    if (new.data ->> 'employerId') is distinct from (old.data ->> 'employerId') then
      raise exception 'employerId change is not allowed';
    end if;
    return new;
  end if;

  -- Не автор: содержание объявления неприкосновенно.
  for k in
    select unnest(array['employerId', 'title', 'description', 'address',
                        'payPerHour', 'workersNeeded', 'date'])
  loop
    if (new.data -> k) is distinct from (old.data -> k) then
      raise exception 'field % of another user job is protected', k;
    end if;
  end loop;

  return new;
end;
$fn$;

drop trigger if exists trg_guard_shared_jobs on public.shared_jobs;
create trigger trg_guard_shared_jobs
  before update on public.shared_jobs
  for each row execute function public.guard_shared_jobs_update();

-- 6. Жалобы должен видеть модератор, иначе модерация невозможна.
drop policy if exists reports_read_moderator on public.reports;
create policy reports_read_moderator on public.reports
  for select to authenticated
  using (exists (select 1 from public.moderators m
                 where m.uid = (auth.uid())::text));

drop policy if exists reports_update_moderator on public.reports;
create policy reports_update_moderator on public.reports
  for update to authenticated
  using (exists (select 1 from public.moderators m
                 where m.uid = (auth.uid())::text))
  with check (exists (select 1 from public.moderators m
                      where m.uid = (auth.uid())::text));

commit;

select tablename, policyname, cmd from pg_policies
where schemaname = 'public' order by tablename, cmd;
