//! Controlador Gráfico del Framebuffer y Consola Visual para AgentOS
//! Renderizado directo sobre VRAM lineal UEFI (resolución nativa y aceleración por software).

use crate::limine::LimineFramebuffer;
use crate::font::{FONT_8X8, FONT_WIDTH, FONT_HEIGHT};
use core::sync::atomic::{AtomicBool, Ordering};

/// Color RGB en formato de 32 bits (0x00RRGGBB)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Color(pub u32);

impl Color {
    pub const BLACK: Self = Self(0x0A0E17);        // Fondo azul noche moderno
    pub const DARK_GRAY: Self = Self(0x1F2430);    // Fondo de paneles y tarjetas
    pub const LIGHT_GRAY: Self = Self(0x707A8A);   // Texto secundario
    pub const WHITE: Self = Self(0xF8F9FA);        // Texto primario
    pub const CYAN: Self = Self(0x00E5FF);         // Acento AgentOS (Cyan eléctrico)
    pub const GREEN: Self = Self(0x00E676);        // Estado OK / verificado
    pub const AMBER: Self = Self(0xFFD600);        // Advertencia / Escrow
    pub const RED: Self = Self(0xFF1744);          // Bloqueado / Excepción
    pub const PURPLE: Self = Self(0xD500F9);       // Multiverso / Causal Merkle
}

/// Estado global del Framebuffer activo
struct FramebufferState {
    ptr: *mut u8,
    width: usize,
    height: usize,
    pitch: usize,
    bpp: usize,
    cursor_x: usize,
    cursor_y: usize,
}

struct FbWrapper(core::cell::UnsafeCell<Option<FramebufferState>>);
unsafe impl Sync for FbWrapper {}

static FB_STATE: FbWrapper = FbWrapper(core::cell::UnsafeCell::new(None));
static FB_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Inicializa el framebuffer gráfico con la información proporcionada por Limine
pub fn init(fb: &'static LimineFramebuffer) {
    unsafe {
        *FB_STATE.0.get() = Some(FramebufferState {
            ptr: fb.address,
            width: fb.width as usize,
            height: fb.height as usize,
            pitch: fb.pitch as usize,
            bpp: fb.bpp as usize,
            cursor_x: 20,
            cursor_y: 60,
        });
    }
    FB_INITIALIZED.store(true, Ordering::Release);

    // Limpiar pantalla con el color de fondo de AgentOS
    clear_screen(Color::BLACK);

    // Dibujar interfaz gráfica inicial
    draw_ui_chrome();
}

/// Dibuja un píxel individual en coordenadas (x, y)
pub fn draw_pixel(x: usize, y: usize, color: Color) {
    if !FB_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    unsafe {
        if let Some(ref state) = &*FB_STATE.0.get() {
            if x < state.width && y < state.height {
                let pixel_offset = y * state.pitch + x * (state.bpp / 8);
                let target = state.ptr.add(pixel_offset) as *mut u32;
                *target = color.0;
            }
        }
    }
}

/// Rellena un rectángulo en coordenadas (x, y) de ancho w y alto h
pub fn fill_rect(x: usize, y: usize, w: usize, h: usize, color: Color) {
    if !FB_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    for cy in y..(y + h) {
        for cx in x..(x + w) {
            draw_pixel(cx, cy, color);
        }
    }
}

/// Dibuja un carácter ASCII usando la fuente de mapa de bits 8x8
pub fn draw_char(c: char, x: usize, y: usize, fg: Color, bg: Color) {
    let ascii = (c as usize).min(127);
    let glyph = FONT_8X8[ascii];

    for row in 0..FONT_HEIGHT {
        let byte = glyph[row];
        for col in 0..FONT_WIDTH {
            let is_set = (byte & (0x80 >> col)) != 0;
            let color = if is_set { fg } else { bg };
            draw_pixel(x + col, y + row, color);
        }
    }
}

/// Dibuja una cadena de texto en coordenadas (x, y)
pub fn draw_string(text: &str, mut x: usize, y: usize, fg: Color, bg: Color) {
    for c in text.chars() {
        if c == '\n' {
            continue;
        }
        draw_char(c, x, y, fg, bg);
        x += FONT_WIDTH;
    }
}

/// Limpia toda la pantalla con un color uniforme
pub fn clear_screen(color: Color) {
    unsafe {
        if let Some(ref state) = &*FB_STATE.0.get() {
            fill_rect(0, 0, state.width, state.height, color);
        }
    }
}

/// Imprime una línea en la consola gráfica con avance de cursor
pub fn console_print(text: &str, fg: Color) {
    if !FB_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    unsafe {
        if let Some(ref mut state) = &mut *FB_STATE.0.get() {
            for c in text.chars() {
                if c == '\n' {
                    state.cursor_x = 24;
                    state.cursor_y += FONT_HEIGHT + 4;
                    if state.cursor_y >= state.height - 40 {
                        state.cursor_y = 60; // Reiniciar arriba en desbordamiento
                    }
                    continue;
                }

                draw_char(c, state.cursor_x, state.cursor_y, fg, Color::BLACK);
                state.cursor_x += FONT_WIDTH;

                if state.cursor_x >= state.width - 40 {
                    state.cursor_x = 24;
                    state.cursor_y += FONT_HEIGHT + 4;
                }
            }
        }
    }
}

/// Dibuja el marco visual y paneles de información del sistema
pub fn draw_ui_chrome() {
    unsafe {
        if let Some(ref state) = &*FB_STATE.0.get() {
            let width = state.width;

            // Barra superior superior (Top Bar)
            fill_rect(0, 0, width, 32, Color::DARK_GRAY);
            draw_string("  AGENTOS ", 12, 12, Color::CYAN, Color::DARK_GRAY);
            draw_string("| Causal Microkernel v0.2.0 (x86-64 Bare-Metal UEFI)", 100, 12, Color::WHITE, Color::DARK_GRAY);
            draw_string("[ SECURE RING 0 ]", width.saturating_sub(180), 12, Color::GREEN, Color::DARK_GRAY);

            // Barra de estado inferior (Bottom Bar)
            fill_rect(0, state.height.saturating_sub(24), width, 24, Color::DARK_GRAY);
            draw_string("  Limine Boot OK  |  UART COM1 [0x3F8]  |  Merkle-DAG Active  |  SchedCP Active", 12, state.height.saturating_sub(16), Color::LIGHT_GRAY, Color::DARK_GRAY);
        }
    }
}

/// Dibuja una tarjeta/panel con borde y título
pub fn draw_panel(x: usize, y: usize, w: usize, h: usize, title: &str, border_color: Color) {
    fill_rect(x, y, w, h, Color::DARK_GRAY);
    // Borde de 1 píxel
    fill_rect(x, y, w, 1, border_color);
    fill_rect(x, y + h - 1, w, 1, border_color);
    fill_rect(x, y, 1, h, border_color);
    fill_rect(x + w - 1, y, 1, h, border_color);

    // Título
    draw_string(title, x + 10, y + 6, border_color, Color::DARK_GRAY);
}
