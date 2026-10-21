create table public.todos (id uuid primary key default gen_random_uuid(), title text not null, user_id uuid references auth.users);
alter table public.todos enable row level security;
create policy "own todos" on public.todos for all using (auth.uid() = user_id);
