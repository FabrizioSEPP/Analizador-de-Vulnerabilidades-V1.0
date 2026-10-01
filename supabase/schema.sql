-- ============================================================================
-- Esquema de la base de datos (Supabase / PostgreSQL)
-- Ejecuta TODO este archivo en el SQL Editor de tu proyecto Supabase.
-- ============================================================================

-- ------------------------------------------------------------- app_users
-- Usuarios de la app. El login es propio (PBKDF2-HMAC-SHA256 + salt),
-- no se usa Supabase Auth.
create table if not exists public.app_users (
    id           uuid primary key default gen_random_uuid(),
    username     text not null unique,
    display_name text not null,
    password     text not null,          -- hash PBKDF2 en hexadecimal
    salt         text not null,          -- salt en hexadecimal
    algo         text not null default 'pbkdf2_sha256',
    iteraciones  integer not null default 200000,
    last_login   timestamptz,
    created_at   timestamptz not null default now()
);

-- ------------------------------------------------------------------ scans
-- Un escaneo por módulo (sqli / load / audit / port).
create table if not exists public.scans (
    id              uuid primary key default gen_random_uuid(),
    username        text not null
                    references public.app_users(username) on delete cascade,
    modulo          text not null,
    url             text not null,
    score           numeric,
    nivel           text,
    total_hallazgos integer not null default 0,
    detalle         text,
    resumen         jsonb not null default '{}'::jsonb,
    created_at      timestamptz not null default now()
);

create index if not exists scans_username_created_idx
    on public.scans (username, created_at desc);

-- ---------------------------------------------------------- scan_findings
-- Hallazgos de cada escaneo (un escaneo puede tener muchos).
create table if not exists public.scan_findings (
    id          uuid primary key default gen_random_uuid(),
    scan_id     uuid not null
                references public.scans(id) on delete cascade,
    tipo        text,
    parametro   text,
    metodo      text,
    severidad   text,
    cvss        numeric,
    confianza   numeric,
    descripcion text,
    explicacion text,
    remediacion text,
    evidencia   text,
    owasp       text,
    motor       text,
    extra       jsonb not null default '{}'::jsonb
);

create index if not exists scan_findings_scan_idx
    on public.scan_findings (scan_id, cvss desc);

-- ======================================================================
-- Seguridad: RLS activada y SIN políticas permisivas.
-- La app se conecta con la clave `service_role`, que omite RLS; la clave
-- pública (anon) queda sin acceso a estas tablas.
-- ======================================================================
alter table public.app_users      enable row level security;
alter table public.scans          enable row level security;
alter table public.scan_findings  enable row level security;

-- (Opcional) Borra usuarios de prueba si ejecutaste esto antes:
-- delete from public.app_users;
