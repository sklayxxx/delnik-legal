-- ============================================================
--  ДЕЛЬНИК · Адрес и координаты — видны всем (v69)
--
--  Что было: job_locations держала RLS «только автор заявки и
--  откликнувшиеся видят адрес/координаты». Клиент из-за этого
--  прятал адрес до отклика (флаг locationHidden) и не ставил
--  такие заявки на карту.
--
--  Решение: адрес/координаты теперь публичны для всех вошедших —
--  политика SELECT using(true). Локация больше не секрет, флаг
--  locationHidden из клиента убран полностью.
--
--  Защита записи сохраняется: вставлять и обновлять строку в
--  job_locations может только АВТОР заявки (проверка по auth.uid()
--  против shared_jobs.data->>'employerId'). Чужие заявки трогать
--  нельзя — ни вставить свою строку на чужой job_id, ни подменить
--  координаты.
--
--  Запуск: SQL Editor в Supabase (Timeweb) -> New query -> Run,
--  или через GitHub:
--    curl -sL https://raw.githubusercontent.com/sklayxxx/delnik-legal/main/15_job_locations_public.sql | docker exec -i supabase-db psql -U postgres -d postgres
--
--  Повторный запуск безопасен (все drop ... if exists).
-- ============================================================

-- --- 1. Снимаем СТАРЫЕ политики RLS с job_locations -----------------
-- Имена политик на сервере могут отличаться (задавались напрямую,
-- не из репозитория), поэтому снимаем ВСЕ политики таблицы.
-- Включая явные drop для типичных имён — лишним не будет.
do $$
declare
  p record;
begin
  for p in
    select policyname
      from pg_policies
     where schemaname = 'public'
       and tablename  = 'job_locations'
  loop
    execute format('drop policy if exists %I on public.job_locations', p.policyname);
  end loop;
end;
$$;

drop policy if exists locations_select   on public.job_locations;
drop policy if exists locations_insert   on public.job_locations;
drop policy if exists locations_update   on public.job_locations;
drop policy if exists locations_delete   on public.job_locations;
drop policy if exists job_locations_select on public.job_locations;
drop policy if exists job_locations_insert on public.job_locations;
drop policy if exists job_locations_update on public.job_locations;
drop policy if exists job_locations_delete on public.job_locations;

alter table public.job_locations enable row level security;

-- --- 2. ЧТЕНИЕ: адрес и координаты видят ВСЕ авторизованные ----------
drop policy if exists locations_public_select on public.job_locations;
create policy locations_public_select on public.job_locations
  for select to authenticated
  using ( true );

-- --- 3. ЗАПИСЬ: только автор заявки --------------------------------
-- Вставлять/обновлять строку локации может только владелец заявки:
-- job_id должен указывать на заявку, где data->>'employerId' = auth.uid().
-- Для INSERT нужна only WITH CHECK (строки ещё нет), для UPDATE —
-- USING + WITH CHECK (нельзя чужую строку превратить в свою).
drop policy if exists locations_owner_write on public.job_locations;
create policy locations_owner_write on public.job_locations
  for insert to authenticated
  with check (
    exists (
      select 1
        from public.shared_jobs j
       where j.id = job_id
         and j.data ->> 'employerId' = auth.uid()::text
    )
  );

drop policy if exists locations_owner_update on public.job_locations;
create policy locations_owner_update on public.job_locations
  for update to authenticated
  using (
    exists (
      select 1
        from public.shared_jobs j
       where j.id = job_id
         and j.data ->> 'employerId' = auth.uid()::text
    )
  )
  with check (
    exists (
      select 1
        from public.shared_jobs j
       where j.id = job_id
         and j.data ->> 'employerId' = auth.uid()::text
    )
  );

-- DELETE-политику сознательно НЕ создаём: удаление строк локации
-- остаётся закрытым для всех (старые политики удаления уже сняты).
-- Если понадобится удалять локацию — только служебный доступ
-- (service_role / postgres), как и раньше в pre-release cleanup.

-- Проверка после применения (в SQL Editor отдельно, от своего аккаунта):
--   select count(*) from public.job_locations;   -- теперь видны ВСЕ строки
--   -- вставка на чужую заявку должна упасть с RLS-ошибкой:
--   insert into public.job_locations (job_id, address, lat, lng)
--   values ('<чужой_job_id>', 'тест', 0, 0);
