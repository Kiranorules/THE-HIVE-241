-- Run once in the Supabase SQL Editor. Then set supabaseUrl and supabaseAnonKey
-- in supabase-config.js, create the administrator in Supabase Auth, and add
-- that user's UUID to hive_admins using the statement at the end of this file.
-- Never expose a service_role key in this static website.

create extension if not exists pgcrypto;

create table if not exists public.site_content (
  key text primary key,
  value jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

create table if not exists public.hive_admins (
  user_id uuid primary key references auth.users(id) on delete cascade
);

create table if not exists public.project_images (
  id uuid primary key default gen_random_uuid(),
  project_id text not null,
  object_path text not null unique,
  name text not null,
  created_at timestamptz not null default now()
);

create or replace function public.is_hive_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.hive_admins
    where user_id = (select auth.uid())
  );
$$;

revoke all on function public.is_hive_admin() from public;
grant execute on function public.is_hive_admin() to authenticated;

alter table public.site_content enable row level security;
alter table public.hive_admins enable row level security;
alter table public.project_images enable row level security;

drop policy if exists "Public can read site content" on public.site_content;
create policy "Public can read site content"
  on public.site_content for select to anon, authenticated using (true);

drop policy if exists "Hive admins can manage site content" on public.site_content;
create policy "Hive admins can manage site content"
  on public.site_content for all to authenticated
  using (public.is_hive_admin()) with check (public.is_hive_admin());

drop policy if exists "Admins can read their own membership" on public.hive_admins;
create policy "Admins can read their own membership"
  on public.hive_admins for select to authenticated using (user_id = (select auth.uid()));

drop policy if exists "Public can read project images" on public.project_images;
create policy "Public can read project images"
  on public.project_images for select to anon, authenticated using (true);

drop policy if exists "Hive admins can manage project images" on public.project_images;
create policy "Hive admins can manage project images"
  on public.project_images for all to authenticated
  using (public.is_hive_admin()) with check (public.is_hive_admin());

grant select on public.site_content to anon, authenticated;
grant insert, update, delete on public.site_content to authenticated;
grant select on public.hive_admins to authenticated;
grant select on public.project_images to anon, authenticated;
grant insert, update, delete on public.project_images to authenticated;

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'site-assets',
  'site-assets',
  true,
  10485760,
  array['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'image/svg+xml']
)
on conflict (id) do update
set public = excluded.public,
    file_size_limit = excluded.file_size_limit,
    allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "Public can view site assets" on storage.objects;
create policy "Public can view site assets"
  on storage.objects for select to anon, authenticated
  using (bucket_id = 'site-assets');

drop policy if exists "Hive admins can upload site assets" on storage.objects;
create policy "Hive admins can upload site assets"
  on storage.objects for insert to authenticated
  with check (bucket_id = 'site-assets' and public.is_hive_admin());

drop policy if exists "Hive admins can update site assets" on storage.objects;
create policy "Hive admins can update site assets"
  on storage.objects for update to authenticated
  using (bucket_id = 'site-assets' and public.is_hive_admin())
  with check (bucket_id = 'site-assets' and public.is_hive_admin());

drop policy if exists "Hive admins can delete site assets" on storage.objects;
create policy "Hive admins can delete site assets"
  on storage.objects for delete to authenticated
  using (bucket_id = 'site-assets' and public.is_hive_admin());

-- Create the administrator in Supabase Auth first, then add their Auth user UUID:
-- insert into public.hive_admins (user_id) values ('AUTH-USER-UUID');
