// SPDX-License-Identifier: Apache-2.0
//! X11 backend. Only place where enigo/x11rb appear.
use super::{InputBackend, MonitorInfo, RawFrame, ScreenBackend};
use enigo::{Button, Coordinate, Direction, Enigo, Key, Keyboard, Mouse, Settings};
use std::sync::Mutex;
use x11rb::connection::Connection;

pub struct X11Screen;
pub struct X11Input {
    agent: Mutex<Enigo>,
}

impl X11Input {
    pub fn new() -> Result<Self, String> {
        Enigo::new(&Settings::default())
            .map(|e| Self {
                agent: Mutex::new(e),
            })
            .map_err(|e| format!("enigo init: {e:?}"))
    }
}

/// List outputs via RandR; fall back to single root-screen entry.
fn list_outputs(
    conn: &x11rb::rust_connection::RustConnection,
    root: x11rb::protocol::xproto::Window,
) -> Vec<MonitorInfo> {
    use x11rb::protocol::randr::ConnectionExt as _;
    let mut out = vec![];
    let Ok(cookie) = conn.randr_get_screen_resources_current(root) else {
        return out;
    };
    let Ok(reply) = cookie.reply() else {
        return out;
    };
    {
        for (i, output) in reply.outputs.iter().enumerate() {
            let Ok(ic) = conn.randr_get_output_info(*output, reply.config_timestamp) else {
                continue;
            };
            let Ok(info) = ic.reply() else { continue };
            if info.crtc != 0 {
                let Ok(cc) = conn.randr_get_crtc_info(info.crtc, reply.config_timestamp) else {
                    continue;
                };
                let Ok(crtc) = cc.reply() else { continue };
                {
                    if crtc.width > 0 {
                        out.push(MonitorInfo {
                            monitor_id: format!("m{i}"),
                            source_width: crtc.width as u32,
                            source_height: crtc.height as u32,
                            is_primary: i == 0,
                        });
                    }
                }
            }
        }
    }
    out
}

impl ScreenBackend for X11Screen {
    fn name(&self) -> &'static str {
        "x11"
    }
    fn monitors(&self) -> Result<Vec<MonitorInfo>, String> {
        let (conn, screen) = x11rb::connect(None).map_err(|e| format!("x11: {e}"))?;
        let root = conn.setup().roots[screen].root;
        let outs = list_outputs(&conn, root);
        if outs.is_empty() {
            use x11rb::protocol::xproto::ConnectionExt as _;
            let g = conn
                .get_geometry(root)
                .map_err(|e| format!("x11: {e}"))?
                .reply()
                .map_err(|e| format!("x11: {e}"))?;
            Ok(vec![MonitorInfo {
                monitor_id: "m0".into(),
                source_width: g.width as u32,
                source_height: g.height as u32,
                is_primary: true,
            }])
        } else {
            Ok(outs)
        }
    }
    fn capture(&self, monitor_id: Option<&str>) -> Result<RawFrame, String> {
        use x11rb::protocol::randr::ConnectionExt as _;
        use x11rb::protocol::xproto::ConnectionExt as _;
        let (conn, screen) = x11rb::connect(None).map_err(|e| format!("x11: {e}"))?;
        let root = conn.setup().roots[screen].root;
        // Resolve monitor rect (default: full root).
        let (ox, oy, w, h, mid) = match monitor_id {
            None | Some("m0") => {
                let g = conn
                    .get_geometry(root)
                    .map_err(|e| format!("x11: {e}"))?
                    .reply()
                    .map_err(|e| format!("x11: {e}"))?;
                (0, 0, g.width as u32, g.height as u32, "m0".to_string())
            }
            Some(id) => {
                let mons = self.monitors()?;
                let (i, m) = mons
                    .iter()
                    .enumerate()
                    .find(|(_, m)| m.monitor_id == id)
                    .ok_or_else(|| "unknown monitor_id".to_string())?;
                // Find crtc offset for monitor i.
                let res = conn
                    .randr_get_screen_resources_current(root)
                    .map_err(|e| format!("x11: {e}"))?
                    .reply()
                    .map_err(|e| format!("x11: {e}"))?;
                let mut n = 0usize;
                let mut rect = None;
                for output in &res.outputs {
                    let info = conn
                        .randr_get_output_info(*output, res.config_timestamp)
                        .map_err(|e| format!("x11: {e}"))?
                        .reply()
                        .map_err(|e| format!("x11: {e}"))?;
                    if info.crtc == 0 {
                        continue;
                    }
                    if n == i {
                        let c = conn
                            .randr_get_crtc_info(info.crtc, res.config_timestamp)
                            .map_err(|e| format!("x11: {e}"))?
                            .reply()
                            .map_err(|e| format!("x11: {e}"))?;
                        rect = Some((c.x as u32, c.y as u32, c.width as u32, c.height as u32));
                        break;
                    }
                    n += 1;
                }
                let (ox, oy, w, h) = rect.unwrap_or((0, 0, m.source_width, m.source_height));
                let _ = i;
                (ox, oy, w, h, m.monitor_id.clone())
            }
        };
        let reply = conn
            .get_image(
                x11rb::protocol::xproto::ImageFormat::Z_PIXMAP,
                root,
                ox as i16,
                oy as i16,
                w as u16,
                h as u16,
                u32::MAX,
            )
            .map_err(|e| format!("x11: {e}"))?
            .reply()
            .map_err(|e| format!("capture: {e}"))?;
        // Assume 32-bit depth: B,G,R,X per pixel.
        let data = reply.data;
        let mut rgba = Vec::with_capacity((w * h * 4) as usize);
        let bpp = (data.len() / (w as usize * h as usize)).max(1);
        if bpp >= 4 {
            for px in data.chunks_exact(bpp) {
                rgba.extend_from_slice(&[px[2], px[1], px[0], 255]);
            }
        } else {
            return Err("unsupported depth".into());
        }
        Ok(RawFrame {
            monitor_id: mid,
            source_width: w,
            source_height: h,
            rgba,
        })
    }
}

fn map_button(b: &str) -> Result<Button, String> {
    match b {
        "left" => Ok(Button::Left),
        "right" => Ok(Button::Right),
        "middle" => Ok(Button::Middle),
        _ => Err("unknown button".into()),
    }
}

fn map_key(k: &str) -> Result<Key, String> {
    match k {
        "Enter" => Ok(Key::Return),
        "Tab" => Ok(Key::Tab),
        "Escape" => Ok(Key::Escape),
        "Backspace" => Ok(Key::Backspace),
        "Delete" => Ok(Key::Delete),
        "Up" => Ok(Key::UpArrow),
        "Down" => Ok(Key::DownArrow),
        "Left" => Ok(Key::LeftArrow),
        "Right" => Ok(Key::RightArrow),
        "F4" => Ok(Key::F4),
        s if s.len() == 1 => Ok(Key::Unicode(s.chars().next().unwrap())),
        _ => Err(format!("unknown key: {k}")),
    }
}

impl InputBackend for X11Input {
    fn name(&self) -> &'static str {
        "x11"
    }
    fn click(&self, x: u32, y: u32, button: &str) -> Result<(), String> {
        let b = map_button(button)?;
        let mut a = self.agent.lock().map_err(|e| e.to_string())?;
        a.move_mouse(x as i32, y as i32, Coordinate::Abs)
            .map_err(|e| format!("{e:?}"))?;
        a.button(b, Direction::Click)
            .map_err(|e| format!("{e:?}"))?;
        Ok(())
    }
    fn type_text(&self, text: &str) -> Result<(), String> {
        self.agent
            .lock()
            .map_err(|e| e.to_string())?
            .text(text)
            .map_err(|e| format!("{e:?}"))
    }
    fn press(&self, key: &str, modifiers: &[String]) -> Result<(), String> {
        let k = map_key(key)?;
        let mut a = self.agent.lock().map_err(|e| e.to_string())?;
        let mut held = vec![];
        for m in modifiers {
            let mk = match m.as_str() {
                "ctrl" => Key::Control,
                "shift" => Key::Shift,
                "alt" => Key::Alt,
                _ => return Err(format!("unknown modifier: {m}")),
            };
            a.key(mk, Direction::Press).map_err(|e| format!("{e:?}"))?;
            held.push(mk);
        }
        let r = a.key(k, Direction::Click).map_err(|e| format!("{e:?}"));
        for mk in held.into_iter().rev() {
            let _ = a.key(mk, Direction::Release);
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::super::{FrameMeta, FrameStore};
    use std::time::Instant;
    #[test]
    fn transform_roundtrip() {
        let m = FrameMeta {
            monitor_id: "m0".into(),
            source_width: 1920,
            source_height: 1080,
            output_width: 1280,
            output_height: 720,
            scale: 1280.0 / 1920.0,
            created: Instant::now(),
        };
        assert_eq!(FrameStore::to_native(&m, 640, 360), Some((960, 540)));
        assert_eq!(FrameStore::to_native(&m, 1280, 0), None);
    }
}
