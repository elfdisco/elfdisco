-- =====================================================================
--  elfdisco gift list — database schema, security & functions
--  Paste this whole file into Supabase → SQL Editor → Run.
--  Safe to re-run: it drops & recreates policies/functions each time.
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- ---------------------------------------------------------------------
--  TABLES
-- ---------------------------------------------------------------------

-- Owners. One row per signed-up account, keyed to Supabase auth.
create table if not exists public.profiles (
  id           uuid primary key references auth.users(id) on delete cascade,
  username     text unique not null,         -- used in the URL: /giftlist/<username>/...
  display_name text,
  created_at   timestamptz not null default now()
);

-- A gift list. A person can have many (this year, next year, archived...).
create table if not exists public.lists (
  id            uuid primary key default gen_random_uuid(),
  owner_id      uuid not null references public.profiles(id) on delete cascade,
  slug          text not null,               -- used in the URL: /giftlist/ed/<slug>
  title         text not null default 'Gift list',
  subtitle      text,
  theme_light   text not null default 'rose-smoke',
  theme_dark    text not null default 'ash',
  surprise_mode boolean not null default true,   -- owner can't see claims unless they reveal
  is_archived   boolean not null default false,
  item_warning  text,                          -- optional note shown as a ⚠ on every item (hover)
  created_at    timestamptz not null default now(),
  unique (owner_id, slug)
);

-- Optional per-list password. Hash lives here, never exposed to the public API.
create table if not exists public.list_secrets (
  list_id       uuid primary key references public.lists(id) on delete cascade,
  password_hash text not null
);

-- Price tiers (the coins guide). Per list, owner-editable.
create table if not exists public.tiers (
  id       uuid primary key default gen_random_uuid(),
  list_id  uuid not null references public.lists(id) on delete cascade,
  coins    int  not null,                    -- 1, 2, 3...
  hint     text not null,                    -- "under £50"
  position int  not null default 0
);

-- Sections ("This year's wishes", "Dream big", "On hold"...).
create table if not exists public.sections (
  id       uuid primary key default gen_random_uuid(),
  list_id  uuid not null references public.lists(id) on delete cascade,
  title    text not null,
  sub      text,
  warning  text,                            -- optional ⚠ note on every item in this section
  visible  boolean not null default true,    -- hidden sections = "on hold", owner-only
  position int not null default 0
);

-- Items.
create table if not exists public.items (
  id         uuid primary key default gen_random_uuid(),
  list_id    uuid not null references public.lists(id) on delete cascade,
  section_id uuid not null references public.sections(id) on delete cascade,
  title      text not null,
  url        text,
  note       text,
  coins      int,                            -- matches a tier; null = "no idea / returnable"
  position   int not null default 0,
  parent_id  uuid references public.items(id) on delete cascade,  -- sub-items / follow-on thoughts
  archived   boolean not null default false,  -- owner moved it to the Archived section
  taken      boolean not null default false,  -- owner marked it taken (visible to everyone)
  taken_note text,                            -- e.g. "Dad's getting this"
  hidden     boolean not null default false,  -- hidden from guests, still visible to the owner
  link_group uuid,                            -- peer-link: items sharing a value are "related"
  created_at timestamptz not null default now()
);

-- Claims. The surprise-sensitive table. Guests write via functions only.
create table if not exists public.claims (
  id            uuid primary key default gen_random_uuid(),
  list_id       uuid not null references public.lists(id) on delete cascade,
  item_id       uuid references public.items(id) on delete cascade,
  claimer_token text not null,               -- random per-browser id, so only the claimer can release
  claimer_name  text not null,
  kind          text not null default 'claimed',  -- 'claimed' (will buy) or 'bought'
  created_at    timestamptz not null default now()
);
-- one active claim per item
create unique index if not exists claims_one_per_item on public.claims(item_id) where item_id is not null;
create index if not exists items_section_idx on public.items(section_id);
create index if not exists sections_list_idx on public.sections(list_id);
create index if not exists claims_list_idx   on public.claims(list_id);

-- ---------------------------------------------------------------------
--  ROW-LEVEL SECURITY
-- ---------------------------------------------------------------------
alter table public.profiles     enable row level security;
alter table public.lists        enable row level security;
alter table public.list_secrets enable row level security;
alter table public.tiers        enable row level security;
alter table public.sections     enable row level security;
alter table public.items        enable row level security;
alter table public.claims       enable row level security;

-- profiles: anyone can read (to resolve a username in a link); you edit only your own.
drop policy if exists p_profiles_read on public.profiles;
drop policy if exists p_profiles_write on public.profiles;
create policy p_profiles_read  on public.profiles for select using (true);
create policy p_profiles_write on public.profiles for all
  using (auth.uid() = id) with check (auth.uid() = id);

-- lists / tiers / sections / items: world-readable (shareable by link); owner-writable.
drop policy if exists p_lists_read on public.lists;
drop policy if exists p_lists_write on public.lists;
create policy p_lists_read  on public.lists for select using (true);
create policy p_lists_write on public.lists for all
  using (auth.uid() = owner_id) with check (auth.uid() = owner_id);

drop policy if exists p_tiers_read on public.tiers;
drop policy if exists p_tiers_write on public.tiers;
create policy p_tiers_read  on public.tiers for select using (true);
create policy p_tiers_write on public.tiers for all
  using (exists (select 1 from public.lists l where l.id = tiers.list_id and l.owner_id = auth.uid()))
  with check (exists (select 1 from public.lists l where l.id = tiers.list_id and l.owner_id = auth.uid()));

drop policy if exists p_sections_read on public.sections;
drop policy if exists p_sections_write on public.sections;
create policy p_sections_read  on public.sections for select using (true);
create policy p_sections_write on public.sections for all
  using (exists (select 1 from public.lists l where l.id = sections.list_id and l.owner_id = auth.uid()))
  with check (exists (select 1 from public.lists l where l.id = sections.list_id and l.owner_id = auth.uid()));

drop policy if exists p_items_read on public.items;
drop policy if exists p_items_write on public.items;
create policy p_items_read  on public.items for select using (
  not hidden
  or exists (select 1 from public.lists l where l.id = items.list_id and l.owner_id = auth.uid())
);  -- hidden items are owner-only
create policy p_items_write on public.items for all
  using (exists (select 1 from public.lists l where l.id = items.list_id and l.owner_id = auth.uid()))
  with check (exists (select 1 from public.lists l where l.id = items.list_id and l.owner_id = auth.uid()));

-- claims: THE surprise rule.
-- Readable by everyone EXCEPT the list's owner (so guests coordinate, owner stays surprised).
-- No write policies at all -> nobody can insert/update/delete directly.
-- All writes go through the SECURITY DEFINER functions below.
drop policy if exists p_claims_read on public.claims;
create policy p_claims_read on public.claims for select
  using (not exists (select 1 from public.lists l where l.id = claims.list_id and l.owner_id = auth.uid()));

-- list_secrets: owner-only; the hash is never reachable by the public API.
drop policy if exists p_secrets_owner on public.list_secrets;
create policy p_secrets_owner on public.list_secrets for all
  using (exists (select 1 from public.lists l where l.id = list_secrets.list_id and l.owner_id = auth.uid()))
  with check (exists (select 1 from public.lists l where l.id = list_secrets.list_id and l.owner_id = auth.uid()));

-- ---------------------------------------------------------------------
--  FUNCTIONS (run with elevated rights, so they bypass the claims rules
--  in a controlled way)
-- ---------------------------------------------------------------------

-- Guest claims an item. Returns true if claimed, false if someone beat them to it.
create or replace function public.claim_item(p_item_id uuid, p_token text, p_name text, p_kind text default 'claimed')
returns boolean language plpgsql security definer set search_path = public as $$
declare inserted int;
begin
  insert into public.claims (item_id, list_id, claimer_token, claimer_name, kind)
    select p_item_id, i.list_id, p_token, coalesce(nullif(trim(p_name),''),'Someone'),
           case when p_kind = 'bought' then 'bought' else 'claimed' end
    from public.items i where i.id = p_item_id
  on conflict (item_id) where item_id is not null do nothing;
  get diagnostics inserted = row_count;
  return inserted > 0;
end $$;

-- Release a claim: automatically on the same browser (token), or from any other
-- device by entering the name it was claimed with. Names aren't shown to guests.
create or replace function public.release_claim(p_item_id uuid, p_token text, p_name text default null)
returns boolean language plpgsql security definer set search_path = public as $$
declare removed int;
begin
  delete from public.claims
   where item_id = p_item_id
     and ( claimer_token = p_token
           or (p_name is not null and lower(claimer_name) = lower(trim(p_name))) );
  get diagnostics removed = row_count;
  return removed > 0;
end $$;

-- Owner's explicit "spoil the surprise" peek. Returns nothing unless the caller
-- is the list's owner, so it's safe to expose.
create or replace function public.reveal_claims(p_list_id uuid)
returns setof public.claims language sql security definer set search_path = public stable as $$
  select c.* from public.claims c
  where c.list_id = p_list_id
    and exists (select 1 from public.lists l where l.id = p_list_id and l.owner_id = auth.uid());
$$;

-- Owner sets or clears a list password.
create or replace function public.set_list_password(p_list_id uuid, p_password text)
returns void language plpgsql security definer set search_path = public, extensions as $$
begin
  if not exists (select 1 from public.lists where id = p_list_id and owner_id = auth.uid()) then
    raise exception 'not the owner of this list';
  end if;
  if p_password is null or length(trim(p_password)) = 0 then
    delete from public.list_secrets where list_id = p_list_id;
  else
    insert into public.list_secrets (list_id, password_hash)
      values (p_list_id, crypt(p_password, gen_salt('bf')))
    on conflict (list_id) do update set password_hash = excluded.password_hash;
  end if;
end $$;

-- Guest checks a password. Returns true if correct (or if no password is set).
create or replace function public.verify_list_password(p_list_id uuid, p_attempt text)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
declare h text;
begin
  select password_hash into h from public.list_secrets where list_id = p_list_id;
  if h is null then return true; end if;
  return h = crypt(coalesce(p_attempt,''), h);
end $$;

-- Does a list have a password? (Boolean only — never leaks the hash.)
create or replace function public.list_has_password(p_list_id uuid)
returns boolean language sql security definer set search_path = public stable as $$
  select exists (select 1 from public.list_secrets where list_id = p_list_id);
$$;

-- Make EXECUTE grants authoritative (Postgres implicitly grants to PUBLIC; revoke that first).
revoke all on function public.claim_item(uuid,text,text,text)   from public;
revoke all on function public.release_claim(uuid,text)          from public;
revoke all on function public.verify_list_password(uuid,text)   from public;
revoke all on function public.list_has_password(uuid)           from public;
revoke all on function public.set_list_password(uuid,text)      from public, anon;
revoke all on function public.reveal_claims(uuid)               from public, anon;

grant execute on function public.claim_item(uuid,text,text,text)   to anon, authenticated;
grant execute on function public.release_claim(uuid,text,text)       to anon, authenticated;
grant execute on function public.verify_list_password(uuid,text)   to anon, authenticated;
grant execute on function public.list_has_password(uuid)           to anon, authenticated;
grant execute on function public.set_list_password(uuid,text)      to authenticated;  -- owner-only
grant execute on function public.reveal_claims(uuid)               to authenticated;  -- owner-only

-- ---------------------------------------------------------------------
--  TABLE PRIVILEGES
--  RLS decides which rows a role sees; the role still needs base grants.
-- ---------------------------------------------------------------------
grant select on public.profiles, public.lists, public.tiers, public.sections, public.items to anon, authenticated;
grant select on public.claims to anon, authenticated;                 -- RLS still hides them from the owner
grant insert, update, delete on public.profiles, public.lists, public.tiers, public.sections, public.items to authenticated;
-- list_secrets: reached only via SECURITY DEFINER functions; no direct role grants.

alter default privileges in schema public grant select on tables to anon;
alter default privileges in schema public grant select, insert, update, delete on tables to authenticated;
