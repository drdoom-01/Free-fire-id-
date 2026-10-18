
create table public.listings (
  id bigint generated always as identity primary key,
  seller_id uuid not null references auth.users(id)
    on delete cascade,
  title text not null
    check (char_length(title) between 3 and 80),
  description text not null
    check (char_length(description) between 5 and 1000),
  player_level integer not null
    check (player_level between 1 and 100),
  price_inr integer not null
    check (price_inr between 1 and 1000000),
  contact_link text,
  status text not null default 'pending'
    check (status in ('pending', 'active', 'rejected')),
  created_at timestamptz not null default now()
);

create table public.user_roles (
  user_id uuid primary key references auth.users(id)
    on delete cascade,
  role text not null check (role in ('admin'))
);

alter table public.listings enable row level security;
alter table public.user_roles enable row level security;

create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.user_roles
    where user_id = (select auth.uid())
      and role = 'admin'
  );
$$;

revoke all on function public.is_admin() from public;
grant execute on function public.is_admin()
to authenticated;

create policy "Public browse active listings"
on public.listings
for select
to anon, authenticated
using (
  status = 'active'
  or seller_id = (select auth.uid())
  or (select public.is_admin())
);

create policy "Signed in users submit listings"
on public.listings
for insert
to authenticated
with check (
  seller_id = (select auth.uid())
  and status = 'pending'
);

create policy "Sellers edit pending listings"
on public.listings
for update
to authenticated
using (
  seller_id = (select auth.uid())
  and status = 'pending'
)
with check (
  seller_id = (select auth.uid())
  and status = 'pending'
);

create policy "Admins manage listings"
on public.listings
for all
to authenticated
using ((select public.is_admin()))
with check ((select public.is_admin()));

create policy "Admins view roles"
on public.user_roles
for select
to authenticated
using ((select public.is_admin()));
