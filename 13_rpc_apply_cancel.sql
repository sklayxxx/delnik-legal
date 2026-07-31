-- ============================================================
--  ДЕЛЬНИК · RPC для отклика/отмены (v67)
--
--  Проблема: клиент при отклике/отмене переписывал всю строку заявки
--  целиком (_pushJobResult делал select + update всего data).
--  Это гоняло большой JSON при каждом действии и создавало гонку:
--  два пользователя, откликнувшихся одновременно, затирали
--  applicants друг друга.
--
--  Решение: серверные функции apply_to_job / cancel_apply меняют
--  только data->applicants АТОМАРНО (jsonb-выражением в самом UPDATE,
--  без чтения и без перезаписи остальных полей). Если двое
--  откликнулись одновременно — оба отклика сохранятся, потому что
--  UPDATE использует текущее значение столбца data.
--
--  Лимит 10/24ч продолжает считать существующий триггер
--  tg_limit_applies (ловит появление пользователя в applicants
--  на любом UPDATE). cancel_apply возвращает запись лимита
--  (удаляет строку rate_events с action='apply'), чтобы клиент
--  и сервер считали одинаково: отменил отклик — место вернулось.
--
--  Совместимость с guard_shared_jobs_update: RPC не меняет ключевые
--  поля чужой заявки и не трогает чужие отклики — только добавляет
--  себя (apply) или убирает себя (cancel), поэтому триггер пропустит.
--
--  Запуск: SQL Editor в Supabase (Timeweb) -> New query -> Run.
--  Функции перезаписываются (create or replace), повторный запуск
--  безопасен.
-- ============================================================

-- ---------- apply_to_job: атомарно добавить в applicants ----------
create or replace function public.apply_to_job(
  p_job_id text,
  p_user_id text
) returns jsonb
language plpgsql
security definer
set search_path = public
as $fn$
declare
  row_data jsonb;
  cur_uid text := (auth.uid())::text;
  is_full bool;
begin
  -- Только сам пользователь может откликнуться за себя.
  if cur_uid is null or cur_uid <> p_user_id then
    raise exception 'PGRST_denied: вы можете откликнуться только за себя';
  end if;

  select data into row_data from public.shared_jobs where id = p_job_id;
  if row_data is null then
    raise exception 'PGRST_not_found: заявка не найдена';
  end if;

  -- Проверки как на клиенте: своя заявка, закрыта, отклонён, места.
  if (row_data ->> 'employerId') = p_user_id then
    raise exception 'Нельзя откликнуться на свою заявку';
  end if;
  if coalesce((row_data ->> 'isClosed')::boolean, false) then
    raise exception 'Заявка закрыта';
  end if;
  if (row_data -> 'applicants') @> to_jsonb(p_user_id) then
    return row_data; -- уже откликнулся, ничего не делаем
  end if;
  if coalesce((row_data -> 'rejectedApplicants') @> to_jsonb(p_user_id), false) then
    raise exception 'Работодатель отклонил вашу заявку';
  end if;

  is_full := jsonb_array_length(coalesce(row_data -> 'applicants', '[]'::jsonb))
      >= coalesce(nullif(row_data ->> 'workersNeeded', '')::int, 1);
  if is_full then
    raise exception 'Мест больше нет';
  end if;

  -- Атомарно: берём ТЕКУЩЕЕ значение data в момент UPDATE и добавляем
  -- себя. Ничей чужой отклик не затирается. Лимит проверит триггер
  -- tg_limit_applies (он видит первое появление пользователя).
  update public.shared_jobs
     set data = jsonb_set(
           data,
           '{applicants}',
           coalesce(data -> 'applicants', '[]'::jsonb) || to_jsonb(p_user_id)
         )
   where id = p_job_id;

  return (select data from public.shared_jobs where id = p_job_id);
end;
$fn$;

-- Только вошедшие (у анонимов auth.uid() пустой, вызов всё равно упадёт).
grant execute on function public.apply_to_job(text, text) to authenticated;

-- ---------- cancel_apply: атомарно убрать из applicants ----------
-- Возвращает лимит: удаляет одну запись rate_events(action='apply')
-- этого пользователя, чтобы клиент и сервер считали одинаково.
create or replace function public.cancel_apply(
  p_job_id text,
  p_user_id text
) returns jsonb
language plpgsql
security definer
set search_path = public
as $fn$
declare
  row_data jsonb;
  cur_uid text := (auth.uid())::text;
begin
  if cur_uid is null or cur_uid <> p_user_id then
    raise exception 'PGRST_denied: вы можете отменить только свой отклик';
  end if;

  select data into row_data from public.shared_jobs where id = p_job_id;
  if row_data is null then
    raise exception 'PGRST_not_found: заявка не найдена';
  end if;

  if not ((row_data -> 'applicants') @> to_jsonb(p_user_id)) then
    return row_data; -- уже не в списке
  end if;

  -- Атомарно убираем ТОЛЬКО себя. guard_shared_jobs_update разрешает
  -- постороннему удалять из applicants только свой id.
  update public.shared_jobs
     set data = jsonb_set(
           data,
           '{applicants}',
           coalesce(data -> 'applicants', '[]'::jsonb) - p_user_id
         )
   where id = p_job_id;

  -- Возвращаем лимит: удаляем нашу самую свежую запись отклика.
  delete from public.rate_events
   where id = (
     select id from public.rate_events
      where user_id = p_user_id
        and action = 'apply'
      order by created_at desc
      limit 1
   );

  return (select data from public.shared_jobs where id = p_job_id);
end;
$fn$;

grant execute on function public.cancel_apply(text, text) to authenticated;

-- Проверка после применения (в SQL Editor отдельно):
--   select public.apply_to_job('<job_id>', '<мой_user_id>');
--   select public.cancel_apply('<job_id>', '<мой_user_id>');
-- auth.uid() возьмётся из JWT текущей сессии.
