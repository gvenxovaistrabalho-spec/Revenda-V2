-- =====================================================================
--  PAINEL DE PEDIDOS - SQL PARA O SUPABASE
--  Cole TUDO no Supabase > SQL Editor > New query > Run
--  Pode rodar mais de uma vez sem problema.
-- =====================================================================

-- 1) Extensão para criptografar senhas
create extension if not exists pgcrypto with schema extensions;

-- 2) TABELAS -----------------------------------------------------------
create table if not exists public.app_users (
  username      text primary key,
  role          text not null check (role in ('admin','producao')),
  password_hash text not null,
  updated_at    timestamptz not null default now()
);

create table if not exists public.app_sessions (
  token      text primary key,
  username   text not null references public.app_users(username) on delete cascade,
  role       text not null,
  expires_at timestamptz not null
);

create table if not exists public.products (
  sku        text primary key,
  name       text not null default '',
  variations text[] not null default '{}',   -- cores / tipos (ex: {Branco,Preto,GG})
  created_at timestamptz not null default now()
);

create table if not exists public.orders (
  id          bigint generated always as identity primary key,
  marketplace text not null check (marketplace in ('mercado_livre','shopee','tiktok','magalu')),
  slot        text not null default 'Sem horário',   -- ex: Amanhã tarde
  order_code  text not null default '',
  notes       text not null default '',
  created_at  timestamptz not null default now()
);

create table if not exists public.order_items (
  id         bigint generated always as identity primary key,
  order_id   bigint not null references public.orders(id) on delete cascade,
  sku        text not null,
  variation  text not null default '',
  quantity   int  not null check (quantity > 0),
  ready      boolean not null default false,
  ready_at   timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists order_items_order_idx on public.order_items(order_id);

-- 3) SEGURANÇA: ninguém acessa as tabelas direto, só pelas funções abaixo
alter table public.app_users    enable row level security;
alter table public.app_sessions enable row level security;
alter table public.products     enable row level security;
alter table public.orders       enable row level security;
alter table public.order_items  enable row level security;

revoke all on public.app_users, public.app_sessions, public.products,
              public.orders,   public.order_items from anon, authenticated;

-- 4) FUNÇÕES -----------------------------------------------------------

-- auxiliar interna (não pode ser chamada de fora)
create or replace function public._role_of(p_token text) returns text
language sql security definer set search_path = public as $$
  select role from app_sessions where token = p_token and expires_at > now()
$$;
revoke all on function public._role_of(text) from public, anon, authenticated;

-- LOGIN
create or replace function public.login(p_username text, p_password text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare u app_users; t text;
begin
  select * into u from app_users where username = lower(trim(p_username));
  if not found or u.password_hash <> crypt(p_password, u.password_hash) then
    raise exception 'Usuário ou senha inválidos';
  end if;
  delete from app_sessions where expires_at < now();
  t := encode(gen_random_bytes(32), 'hex');
  insert into app_sessions(token, username, role, expires_at)
    values (t, u.username, u.role, now() + interval '30 days');
  return json_build_object('token', t, 'role', u.role, 'username', u.username);
end $$;

-- LOGOUT
create or replace function public.logout(p_token text) returns void
language sql security definer set search_path = public as $$
  delete from app_sessions where token = p_token
$$;

-- SESSÃO ATUAL
create or replace function public.get_session(p_token text) returns json
language plpgsql security definer set search_path = public as $$
declare s app_sessions;
begin
  select * into s from app_sessions where token = p_token and expires_at > now();
  if not found then raise exception 'Sessão expirada'; end if;
  return json_build_object('role', s.role, 'username', s.username);
end $$;

-- PRODUTOS (só admin)
create or replace function public.list_products(p_token text) returns json
language plpgsql security definer set search_path = public as $$
begin
  if public._role_of(p_token) is distinct from 'admin' then raise exception 'Sem permissão'; end if;
  return (select coalesce(json_agg(p order by p.sku), '[]'::json) from products p);
end $$;

create or replace function public.upsert_product(p_token text, p_sku text, p_name text, p_variations text[]) returns void
language plpgsql security definer set search_path = public as $$
begin
  if public._role_of(p_token) is distinct from 'admin' then raise exception 'Sem permissão'; end if;
  if trim(coalesce(p_sku,'')) = '' then raise exception 'Informe o SKU'; end if;
  insert into products(sku, name, variations)
    values (upper(trim(p_sku)), coalesce(trim(p_name),''), coalesce(p_variations,'{}'))
  on conflict (sku) do update set name = excluded.name, variations = excluded.variations;
end $$;

create or replace function public.delete_product(p_token text, p_sku text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if public._role_of(p_token) is distinct from 'admin' then raise exception 'Sem permissão'; end if;
  delete from products where sku = p_sku;
end $$;

-- PEDIDOS: listar (admin e produção)
create or replace function public.list_orders(p_token text) returns json
language plpgsql security definer set search_path = public as $$
begin
  if public._role_of(p_token) is null then raise exception 'Sessão expirada'; end if;
  return (
    select coalesce(json_agg(x order by x.created_at desc), '[]'::json) from (
      select o.id, o.marketplace, o.slot, o.order_code, o.notes, o.created_at,
        (select coalesce(json_agg(json_build_object(
                  'id', i.id, 'sku', i.sku, 'name', coalesce(p.name,''),
                  'variation', i.variation, 'quantity', i.quantity, 'ready', i.ready
                ) order by i.id), '[]'::json)
           from order_items i left join products p on p.sku = i.sku
          where i.order_id = o.id) as items
      from orders o
    ) x
  );
end $$;

-- PEDIDOS: criar (só admin). p_items = [{"sku":"X","variation":"Branco","quantity":2}, ...]
create or replace function public.create_order(
  p_token text, p_marketplace text, p_slot text, p_code text, p_notes text, p_items jsonb
) returns bigint
language plpgsql security definer set search_path = public as $$
declare new_id bigint; it jsonb;
begin
  if public._role_of(p_token) is distinct from 'admin' then raise exception 'Sem permissão'; end if;
  if p_items is null or jsonb_array_length(p_items) = 0 then raise exception 'Adicione pelo menos um item'; end if;
  insert into orders(marketplace, slot, order_code, notes)
    values (p_marketplace, coalesce(nullif(p_slot,''),'Sem horário'), coalesce(trim(p_code),''), coalesce(trim(p_notes),''))
    returning id into new_id;
  for it in select jsonb_array_elements(p_items) loop
    insert into order_items(order_id, sku, variation, quantity)
      values (new_id, upper(trim(it->>'sku')), coalesce(it->>'variation',''), (it->>'quantity')::int);
  end loop;
  return new_id;
end $$;

create or replace function public.add_item(p_token text, p_order_id bigint, p_sku text, p_variation text, p_quantity int) returns void
language plpgsql security definer set search_path = public as $$
begin
  if public._role_of(p_token) is distinct from 'admin' then raise exception 'Sem permissão'; end if;
  insert into order_items(order_id, sku, variation, quantity)
    values (p_order_id, upper(trim(p_sku)), coalesce(p_variation,''), p_quantity);
end $$;

create or replace function public.update_item(p_token text, p_item_id bigint, p_variation text, p_quantity int) returns void
language plpgsql security definer set search_path = public as $$
begin
  if public._role_of(p_token) is distinct from 'admin' then raise exception 'Sem permissão'; end if;
  update order_items set variation = coalesce(p_variation, variation), quantity = p_quantity where id = p_item_id;
end $$;

create or replace function public.delete_item(p_token text, p_item_id bigint) returns void
language plpgsql security definer set search_path = public as $$
begin
  if public._role_of(p_token) is distinct from 'admin' then raise exception 'Sem permissão'; end if;
  delete from order_items where id = p_item_id;
end $$;

create or replace function public.delete_order(p_token text, p_order_id bigint) returns void
language plpgsql security definer set search_path = public as $$
begin
  if public._role_of(p_token) is distinct from 'admin' then raise exception 'Sem permissão'; end if;
  delete from orders where id = p_order_id;
end $$;

-- PRONTO / PENDENTE (admin e produção) - é a ÚNICA coisa que a produção altera
create or replace function public.set_item_ready(p_token text, p_item_id bigint, p_ready boolean) returns void
language plpgsql security definer set search_path = public as $$
begin
  if public._role_of(p_token) is null then raise exception 'Sessão expirada'; end if;
  update order_items
     set ready = p_ready, ready_at = case when p_ready then now() else null end
   where id = p_item_id;
end $$;

-- SENHAS (só admin)
create or replace function public.list_users(p_token text) returns json
language plpgsql security definer set search_path = public as $$
begin
  if public._role_of(p_token) is distinct from 'admin' then raise exception 'Sem permissão'; end if;
  return (select coalesce(json_agg(json_build_object('username', username, 'role', role) order by role), '[]'::json) from app_users);
end $$;

create or replace function public.change_password(p_token text, p_username text, p_new text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if public._role_of(p_token) is distinct from 'admin' then raise exception 'Sem permissão'; end if;
  if length(coalesce(p_new,'')) < 4 then raise exception 'A senha precisa ter pelo menos 4 caracteres'; end if;
  update app_users set password_hash = crypt(p_new, gen_salt('bf')), updated_at = now()
   where username = p_username;
  if not found then raise exception 'Usuário não existe'; end if;
  delete from app_sessions where username = p_username and token <> p_token;  -- derruba logins antigos
end $$;

-- 5) PERMISSÃO PARA O SITE CHAMAR AS FUNÇÕES
grant execute on function
  public.login(text,text), public.logout(text), public.get_session(text),
  public.list_products(text), public.upsert_product(text,text,text,text[]), public.delete_product(text,text),
  public.list_orders(text), public.create_order(text,text,text,text,text,jsonb),
  public.add_item(text,bigint,text,text,int), public.update_item(text,bigint,text,int),
  public.delete_item(text,bigint), public.delete_order(text,bigint),
  public.set_item_ready(text,bigint,boolean),
  public.list_users(text), public.change_password(text,text,text)
to anon, authenticated;

-- 6) AS DUAS CONTAS (troque as senhas depois, pelo painel do site)
--    admin    / admin123
--    producao / producao123
insert into public.app_users(username, role, password_hash) values
  ('admin',    'admin',    extensions.crypt('admin123',    extensions.gen_salt('bf'))),
  ('producao', 'producao', extensions.crypt('producao123', extensions.gen_salt('bf')))
on conflict (username) do nothing;
