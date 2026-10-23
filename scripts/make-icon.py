"""Draws the NetWarden icon (blue tile, download/upload arrows) into a multi-size .ico.

Usage: python scripts/make-icon.py src/NetWarden.Client/Assets/NetWarden.ico
"""
import sys
from PIL import Image, ImageDraw

SIZES = [16, 20, 24, 32, 40, 48, 64, 128, 256]
SCALE = 4  # draw large, then downsample for smooth edges


def lerp(a, b, t):
    return tuple(round(x + (y - x) * t) for x, y in zip(a, b))


def draw(size):
    n = size * SCALE
    img = Image.new("RGBA", (n, n), (0, 0, 0, 0))

    # Rounded tile with a vertical gradient.
    top, bottom = (37, 99, 235), (30, 58, 138)
    gradient = Image.new("RGBA", (n, n))
    g = ImageDraw.Draw(gradient)
    for y in range(n):
        g.line([(0, y), (n, y)], fill=lerp(top, bottom, y / n) + (255,))
    mask = Image.new("L", (n, n), 0)
    pad = round(n * 0.04)
    ImageDraw.Draw(mask).rounded_rectangle([pad, pad, n - pad, n - pad], radius=round(n * 0.22), fill=255)
    img.paste(gradient, (0, 0), mask)

    d = ImageDraw.Draw(img)
    stroke = max(round(n * 0.085), 1)
    head = round(n * 0.14)

    def arrow(x, y0, y1, color):
        # Shaft from y0 to y1, head at y1.
        down = y1 > y0
        tip = y1
        base = y1 - head if down else y1 + head
        d.line([(x, y0), (x, base)], fill=color, width=stroke)
        d.polygon([(x - head, base), (x + head, base), (x, tip)], fill=color)

    arrow(round(n * 0.34), round(n * 0.22), round(n * 0.78), (255, 255, 255, 255))   # download
    arrow(round(n * 0.66), round(n * 0.78), round(n * 0.22), (251, 146, 60, 255))    # upload
    return img.resize((size, size), Image.LANCZOS)


def main(path):
    images = [draw(s) for s in SIZES]
    images[-1].save(path, format="ICO", sizes=[(s, s) for s in SIZES], append_images=images[:-1])
    images[-1].save(path.rsplit(".", 1)[0] + ".png")


if __name__ == "__main__":
    main(sys.argv[1])
