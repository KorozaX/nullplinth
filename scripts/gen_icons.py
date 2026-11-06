"""Generate NULLPLINTH icon set (deterministic, no external assets)."""
from PIL import Image, ImageDraw
import os

OUT = r"C:\Users\Koroza\Documents\deepseek-harness\Network Monitor\NULLPLINTH\src-tauri\icons"
os.makedirs(OUT, exist_ok=True)

BG = (15, 15, 16, 255)
FG = (236, 234, 228, 255)
RED = (194, 48, 42, 255)

def draw(size):
    s = size * 4
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    r = int(s * 0.18)
    d.rounded_rectangle([0, 0, s - 1, s - 1], radius=r, fill=BG)
    # plinth: solid base bar
    d.rectangle([s * 0.22, s * 0.70, s * 0.78, s * 0.78], fill=RED)
    # column
    d.rectangle([s * 0.45, s * 0.18, s * 0.55, s * 0.70], fill=FG)
    # capital
    d.rectangle([s * 0.33, s * 0.18, s * 0.67, s * 0.25], fill=FG)
    return img.resize((size, size), Image.LANCZOS)

for name, size in [("32x32.png", 32), ("128x128.png", 128), ("128x128@2x.png", 256), ("icon.png", 512)]:
    draw(size).save(os.path.join(OUT, name))

sizes = [16, 24, 32, 48, 64, 128, 256]
imgs = [draw(s) for s in sizes]
imgs[0].save(os.path.join(OUT, "icon.ico"), format="ICO", sizes=[(s, s) for s in sizes], append_images=imgs[1:])
print("icons written:", sorted(os.listdir(OUT)))
