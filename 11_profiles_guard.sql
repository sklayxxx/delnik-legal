-- ============================================================
--  ДЕЛЬНИК · Защита профилей от перезаписи (готовится под новый сервер)
--
--  Проблема: клиент пишет чужие строки shared_profiles целиком
--  (_pushProfile(other) при оценках и зачёте работы). RLS это
--  разрешает, значит любой вошедший может испортить чужой профиль:
--  переписать имя, город, возраст и даже снять себе бан.
--
--  Решение: триггер guard_profiles_write.
--    • владелец строки пишет всё (свой профиль);
--    • НЕ владелец может менять ТОЛЬКО агрегаты рейтингов
--      (rating, ratingCount, employerRating, employerRatingCount,
--      completedJobs) — их шлёт клиент при оценке/зачёте;
--    • попытка изменить личные поля чужого профиля → ошибка.
--
--  Статус: клиент УЖЕ переведён на RPC для оценок (update_rating
--  в 14_rpc_rating.sql пишет только агрегаты рейтингов, а не весь
--  профиль), поэтому guard можно применять. Остальные записи чужих
--  профилей клиентом не производятся: свой профиль пишет только
--  владелец (guard пропускает), а отклики/оценки идут через RPC.
--
--  Запуск: docker exec -i supabase-db psql -U postgres -d postgres < файл
-- ============================================================

begin;

create or replace function public.guard_profiles_write()
returns trigger
language plpgsql
security definer
set search_path = public
as $fn$
declare
  caller text := (auth.uid())::text;
  k text;
begin
  -- Обслуживание через psql (без пользовательской сессии) не ограничиваем.
  if caller is null then
    return new;
  end if;

  -- Новые строки создаёт только владелец (регистрация профиля).
  -- Чужой профиль нельзя создать «с нуля».
  if tg_op = 'INSERT' then
    if caller = (new.id)::text then
      return new;
    end if;
    raise exception 'only the owner can create a profile';
  end if;

  -- Владелец строки пишет всё.
  if caller = (new.id)::text then
    return new;
  end if;

  -- Не владелец: личные поля неприкосновенны, менять можно только рейтинги.
  for k in select unnest(array[
      'name', 'city', 'age', 'registered', 'loggedOutAt', 'createdAt',
      'bannedUntil', 'banReason'
    ])
  loop
    if (new.data -> k) is distinct from (old.data -> k) then
      raise exception 'profile field % of another user is protected', k;
    end if;
  end loop;

  return new;
end;
$fn$;

drop trigger if exists trg_guard_profiles_write on public.shared_profiles;
create trigger trg_guard_profiles_write
  before insert or update on public.shared_profiles
  for each row execute function public.guard_profiles_write();

commit;

-- Имперсонация-тесты (запускать отдельно, не в файле):
--   begin;
--   set local role authenticated;
--   set local request.jwt.claims = '{"sub":"<владелец>"}';
--   -- владелец пишет имя себе: должно пройти
--   update public.shared_profiles set data = jsonb_set(data,'{name}','"Новое"') where id = '<владелец>';
--   rollback;
--
--   begin;
--   set local role authenticated;
--   set local request.jwt.claims = '{"sub":"<чужой>"}';
--   -- чужой меняет имя чужого профиля: должно УПАСТЬ с ошибкой
--   update public.shared_profiles set data = jsonb_set(data,'{name}','"Хак"') where id = '<владелец>';
--   rollback;
--
--   begin;
--   set local role authenticated;
--   set local request.jwt.claims = '{"sub":"<чужой>"}';
--   -- чужой пишет рейтинг в чужой профиль: должно ПРОЙТИ (оценка работника)
--   update public.shared_profiles
--     set data = jsonb_set(jsonb_set(data,'{rating}','4.5'),'{ratingCount}','11')
--     where id = '<владелец>';
--   rollback;
