## Remnawave Subscription Page

Learn more about Remnawave [here](https://docs.rw/).

The backend is written in Rust ([axum](https://github.com/tokio-rs/axum) / [hyper](https://hyper.rs));
the frontend is a React SPA (`frontend/`) that the backend serves.

### Layout

| Path        | What                                                                    |
| ----------- | ----------------------------------------------------------------------- |
| `backend/`  | Rust service: panel API client, subscription proxy, HTML page, sessions |
| `frontend/` | React SPA, built with Vite into `frontend/dist`                         |

### Configuration

See [`.env.sample`](.env.sample). Variables are unchanged from the Node.js version, with these notes:

- `INTERNAL_JWT_SECRET` is generated at startup when not set (the Docker entrypoint script is gone).
- `FRONTEND_DIR` (optional) overrides where `index.html` and `assets/` are read from
  (`/opt/app/frontend`, or `./dev_frontend` when `NODE_ENV=development`).
- `ENABLE_DEBUG_LOGS=true` / `NODE_ENV=development` enable debug logging; `RUST_LOG` overrides the filter.
- `SUBSCRIPTION_PAGE_INSTANCES` no longer exists: there is no pm2 and no cluster mode, a single
  process uses all cores.

### Development

```bash
make test        # backend unit + end-to-end tests (against a mock panel)
make lint        # rustfmt + clippy

# frontend: build once, then serve it from the backend
cd frontend && npm ci && npm run start:build && cp -r dist ../backend/dev_frontend
cd ../backend && NODE_ENV=development cargo run
```

`rw-subpage --healthcheck` probes `/internal/health` on loopback; the Docker `HEALTHCHECK` uses it.

# Contributors

Check [open issues](https://github.com/remnawave/subscription-page/issues) to help the progress of this project.

<p align="center">
Thanks to the all contributors who have helped improve Remnawave:
</p>
<p align="center">
<a href="https://github.com/remnawave/subscription-page/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=remnawave/subscription-page" />
</a>
</p>
