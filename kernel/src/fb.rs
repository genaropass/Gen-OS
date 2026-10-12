//! Controlador Gráfico del Framebuffer y Consola Visual para AgentOS
//! Renderizado directo sobre VRAM lineal UEFI (resolución nativa y aceleración por software).
//! Protegido contra concurrencia con interrupciones mediante `IrqSpinLock`.

use crate::limine::LimineFramebuffer;
use crate::font::{FONT_8X8, FONT_WIDTH, FONT_HEIGHT};
use crate::sync::IrqSpinLock;

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
pub struct FramebufferState {
    ptr: *mut u8,
    width: usize,
    height: usize,
    pitch: usize,
    bpp: usize,
    cursor_x: usize,
    cursor_y: usize,
}

unsafe impl Send for FramebufferState {}

impl FramebufferState {
    pub fn draw_pixel(&mut self, x: usize, y: usize, color: Color) {
        if x < self.width && y < self.height {
            let pixel_offset = y * self.pitch + x * (self.bpp / 8);
            unsafe {
                let target = self.ptr.add(pixel_offset) as *mut u32;
                *target = color.0;
            }
        }
    }

    pub fn fill_rect(&mut self, x: usize, y: usize, w: usize, h: usize, color: Color) {
        for cy in y..(y + h) {
            for cx in x..(x + w) {
                self.draw_pixel(cx, cy, color);
            }
        }
    }

    pub fn draw_char(&mut self, c: char, x: usize, y: usize, fg: Color, bg: Color) {
        let ascii = (c as usize).min(127);
        let glyph = FONT_8X8[ascii];

        for row in 0..FONT_HEIGHT {
            let byte = glyph[row];
            for col in 0..FONT_WIDTH {
                let is_set = (byte & (0x80 >> col)) != 0;
                let color = if is_set { fg } else { bg };
                self.draw_pixel(x + col, y + row, color);
            }
        }
    }

    pub fn draw_string(&mut self, text: &str, mut x: usize, y: usize, fg: Color, bg: Color) {
        for c in text.chars() {
            if c == '\n' {
                continue;
            }
            self.draw_char(c, x, y, fg, bg);
            x += FONT_WIDTH;
        }
    }

    pub fn clear_screen(&mut self, color: Color) {
        let (w, h) = (self.width, self.height);
        self.fill_rect(0, 0, w, h, color);
    }

    pub fn console_print(&mut self, text: &str, fg: Color) {
        for c in text.chars() {
            if c == '\n' {
                self.cursor_x = 24;
                self.cursor_y += FONT_HEIGHT + 4;
                if self.cursor_y >= self.height.saturating_sub(40) {
                    self.cursor_y = 60;
                }
                continue;
            }

            self.draw_char(c, self.cursor_x, self.cursor_y, fg, Color::BLACK);
            self.cursor_x += FONT_WIDTH;

            if self.cursor_x >= self.width.saturating_sub(40) {
                self.cursor_x = 24;
                self.cursor_y += FONT_HEIGHT + 4;
            }
        }
    }

    pub fn draw_ui_chrome(&mut self) {
        let width = self.width;
        let height = self.height;

        // Barra superior (Top Bar)
        self.fill_rect(0, 0, width, 32, Color::DARK_GRAY);
        self.draw_string("  AGENTOS ", 12, 12, Color::CYAN, Color::DARK_GRAY);
        self.draw_string("| Causal Microkernel v0.2.0 (x86-64 Bare-Metal UEFI)", 100, 12, Color::WHITE, Color::DARK_GRAY);
        self.draw_string("[ SECURE RING 0 ]", width.saturating_sub(180), 12, Color::GREEN, Color::DARK_GRAY);

        // Barra de estado inferior (Bottom Bar)
        self.fill_rect(0, height.saturating_sub(24), width, 24, Color::DARK_GRAY);
        self.draw_string("  Limine Boot OK  |  UART COM1 [0x3F8]  |  Merkle-DAG Active  |  Preempt OK", 12, height.saturating_sub(16), Color::LIGHT_GRAY, Color::DARK_GRAY);
    }

    pub fn draw_panel(&mut self, x: usize, y: usize, w: usize, h: usize, title: &str, border_color: Color) {
        self.fill_rect(x, y, w, h, Color::DARK_GRAY);
        // Borde de 1 píxel
        self.fill_rect(x, y, w, 1, border_color);
        self.fill_rect(x, y + h.saturating_sub(1), w, 1, border_color);
        self.fill_rect(x, y, 1, h, border_color);
        self.fill_rect(x + w.saturating_sub(1), y, 1, h, border_color);

        // Título
        self.draw_string(title, x + 10, y + 6, border_color, Color::DARK_GRAY);
    }
}

static FB_STATE: IrqSpinLock<Option<FramebufferState>> = IrqSpinLock::new(None);

/// Inicializa el framebuffer gráfico con la información proporcionada por Limine
pub fn init(fb: &'static LimineFramebuffer) {
    let mut state = FB_STATE.lock();
    *state = Some(FramebufferState {
        ptr: fb.address,
        width: fb.width as usize,
        height: fb.height as usize,
        pitch: fb.pitch as usize,
        bpp: fb.bpp as usize,
        cursor_x: 20,
        cursor_y: 60,
    });

    if let Some(ref mut s) = *state {
        s.clear_screen(Color::BLACK);
        s.draw_ui_chrome();
    }
}

/// Dibuja un píxel individual en coordenadas (x, y)
pub fn draw_pixel(x: usize, y: usize, color: Color) {
    if let Some(ref mut s) = *FB_STATE.lock() {
        s.draw_pixel(x, y, color);
    }
}

/// Rellena un rectángulo en coordenadas (x, y) de ancho w y alto h
pub fn fill_rect(x: usize, y: usize, w: usize, h: usize, color: Color) {
    if let Some(ref mut s) = *FB_STATE.lock() {
        s.fill_rect(x, y, w, h, color);
    }
}

/// Dibuja un carácter ASCII usando la fuente de mapa de bits 8x8
pub fn draw_char(c: char, x: usize, y: usize, fg: Color, bg: Color) {
    if let Some(ref mut s) = *FB_STATE.lock() {
        s.draw_char(c, x, y, fg, bg);
    }
}

/// Dibuja una cadena de texto en coordenadas (x, y)
pub fn draw_string(text: &str, x: usize, y: usize, fg: Color, bg: Color) {
    if let Some(ref mut s) = *FB_STATE.lock() {
        s.draw_string(text, x, y, fg, bg);
    }
}

/// Limpia toda la pantalla con un color uniforme
pub fn clear_screen(color: Color) {
    if let Some(ref mut s) = *FB_STATE.lock() {
        s.clear_screen(color);
    }
}

/// Imprime una línea en la consola gráfica con avance de cursor
pub fn console_print(text: &str, fg: Color) {
    if let Some(ref mut s) = *FB_STATE.lock() {
        s.console_print(text, fg);
    }
}

/// Dibuja el marco visual y paneles de información del sistema
pub fn draw_ui_chrome() {
    if let Some(ref mut s) = *FB_STATE.lock() {
        s.draw_ui_chrome();
    }
}

/// Dibuja una tarjeta/panel con borde y título
pub fn draw_panel(x: usize, y: usize, w: usize, h: usize, title: &str, border_color: Color) {
    if let Some(ref mut s) = *FB_STATE.lock() {
        s.draw_panel(x, y, w, h, title, border_color);
    }
}
