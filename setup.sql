-- Cole tudo isto no Supabase: SQL Editor > New query > Run

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  name text,
  role text not null default 'user'
);

create table public.orders (
  id bigint generated always as identity primary key,
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  owner_name text,
  reseller text not null,
  product text not null,
  qty int not null check (qty > 0),
  unit_price numeric(10,2),
  status text not null default 'Novo',
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;
alter table public.orders enable row level security;

create function public.is_admin() returns boolean
language sql security definer set search_path = public stable as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin')
$$;

create function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, name)
  values (new.id, coalesce(new.raw_user_meta_data->>'name', new.email));
  return new;
end $$;

create trigger on_auth_user_created
after insert on auth.users
for each row execute function public.handle_new_user();

create policy "profiles_select" on public.profiles for select using (id = auth.uid() or public.is_admin());
create policy "orders_select" on public.orders for select using (user_id = auth.uid() or public.is_admin());
create policy "orders_insert" on public.orders for insert with check (user_id = auth.uid());
create policy "orders_update_admin" on public.orders for update using (public.is_admin());
create policy "orders_delete_admin" on public.orders for delete using (public.is_admin());

-- Se você JÁ rodou a versão antiga deste arquivo, rode só esta linha:
-- alter table public.orders add column unit_price numeric(10,2);

-- DEPOIS de criar sua conta no site, rode isto (troque pelo seu e-mail) para virar ADMIN:
-- update public.profiles set role = 'admin' where id = (select id from auth.users where email = 'SEU@EMAIL.COM');
