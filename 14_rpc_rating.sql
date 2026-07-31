-- ============================================================
--  ДЕЛЬНИК · RPC для оценок (v68)
--
--  Проблема: клиент при оценке исполнителя/работодателя писал
--  ВЕСЬ профиль оцениваемого (_pushProfile(other) = toSharedJson),
--  т.е. любой вошедший мог перезаписать чужое имя/город/возраст
--  устаревшими данными из своего кэша. Из-за этого нельзя было
--  включить guard_profiles_write (он отклонил бы запись целиком,
--  и оценка бы потерялась).
--
--  Решение: update_rating меняет ТОЛЬКО агрегаты рейтингов
--  (rating, ratingCount, employerRating, employerRatingCount,
--  completedJobs) через jsonb_set — атомарно, без чтения и без
--  перезаписи личных полей. Совместим с guard_profiles_write,
--  который для не-владельца разрешает менять именно эти 5 полей.
--
--  Клиент по-прежнему сам считает агрегаты (как и раньше) и шлёт
--  готовые числа; RPC просто применяет их. Смена агрегатов идёт
--  одной записью, поэтому одновременные оценки двух пользователей
--  не затирают друг друга (последний wins — как и было).
--
--  Запуск: SQL Editor в Supabase (Timeweb) -> New query -> Run.
--  Функция перезаписывается (create or replace), повторный запуск
--  безопасен.
-- ============================================================

create or replace function public.update_rating(
  p_target_id text,
  p_rating numeric,
  p_rating_count int,
  p_employer_rating numeric,
  p_employer_rating_count int,
  p_completed_jobs int
) returns jsonb
language plpgsql
security definer
set search_path = public
as $fn$
declare
  cur_uid text := (auth.uid())::text;
  row_data jsonb;
  updated jsonb;
begin
  -- Оценка — всегда чужой профиль (оценить себя нельзя).
  if cur_uid is null or cur_uid = p_target_id then
    raise exception 'PGRST_denied: нельзя оценить себя';
  end if;

  select data into row_data from public.shared_profiles where id = p_target_id;
  if row_data is null then
    raise exception 'PGRST_not_found: профиль не найден';
  end if;

  -- Обновляем ТОЛЬКО агрегаты рейтингов. Личные поля (name, city, age
  -- и пр.) не трогаем — guard_profiles_write разрешит эту запись.
  updated := jsonb_set(row_data, '{rating}', to_jsonb(p_rating));
  updated := jsonb_set(updated, '{ratingCount}', to_jsonb(p_rating_count));
  updated := jsonb_set(updated, '{employerRating}', to_jsonb(p_employer_rating));
  updated := jsonb_set(updated, '{employerRatingCount}', to_jsonb(p_employer_rating_count));
  updated := jsonb_set(updated, '{completedJobs}', to_jsonb(p_completed_jobs));

  update public.shared_profiles
     set data = updated,
         updated_at = now()
   where id = p_target_id;

  return updated;
end;
$fn$;

-- Только вошедшие (анонимам нечего оценивать).
grant execute on function public.update_rating(
  text, numeric, int, numeric, int, int) to authenticated;

-- Проверка после применения (в SQL Editor отдельно):
--   select public.update_rating(
--     '<target_id>', 4.5, 11, 0, 0, 3
--   );
-- auth.uid() возьмётся из JWT текущей сессии.
