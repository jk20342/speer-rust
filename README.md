# speer

safe rust wrapper for speer.

use this when you want rust types around the main speer host / peer / stream
api. raw c bindings live in `speer-sys`.

the wrapper keeps host-owned peers tied to the host lifetime, and streams tied
to the peer lifetime. the unsafe calls stay inside the crate.

## build

```bash
cargo check
```

## use

```toml
[dependencies]
speer = "0.1"
```

or from this workspace:

```toml
[dependencies]
speer = { path = "../speer" }
```

## tiny shape

```rust
let seed = [8u8; speer::PRIVATE_KEY_SIZE];
let mut host = speer::Host::new(&seed, None)?;

host.set_callback(|event| {
    println!("{:?}", event.event_type);
});

while running {
    host.poll(100);
}
```

## features

- `build-from-source` - build the c library with cmake
- `libp2p-tcp` - expose the low-level libp2p tcp bindings through `speer-sys`
- `full-chat` - expose everything the chat app needs

if this gets split out, the repo name should be `speer-rust`.
