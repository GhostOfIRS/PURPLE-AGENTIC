from PIL import Image, ImageDraw, ImageFilter

SIZE = 1024
img = Image.new("RGBA", (SIZE, SIZE), (10, 7, 22, 255))
draw = ImageDraw.Draw(img)


def lerp(a, b, t):
    return int(a + (b - a) * t)


# Background gradient
for y in range(SIZE):
    t = y / (SIZE - 1)
    color = (
        lerp(18, 5, t),
        lerp(10, 12, t),
        lerp(40, 26, t),
        255,
    )
    draw.line((0, y, SIZE, y), fill=color)

# Neon glow layers
glow = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
gdraw = ImageDraw.Draw(glow)

gdraw.ellipse((180, 140, 844, 804), fill=(100, 40, 220, 55))
gdraw.ellipse((250, 230, 774, 754), fill=(0, 255, 220, 40))
gdraw.rounded_rectangle((210, 210, 814, 814), radius=120, outline=(180, 90, 255, 90), width=10)

# Circuit lines
for x in range(120, 920, 90):
    gdraw.line((x, 100, x, 280), fill=(0, 255, 200, 70), width=4)
    gdraw.line((x, 780, x, 940), fill=(0, 255, 200, 70), width=4)
for y in range(140, 900, 90):
    gdraw.line((90, y, 260, y), fill=(170, 80, 255, 60), width=4)
    gdraw.line((764, y, 934, y), fill=(170, 80, 255, 60), width=4)

glow = glow.filter(ImageFilter.GaussianBlur(18))
img = Image.alpha_composite(img, glow)
draw = ImageDraw.Draw(img)

# Central shield
shield = [
    (512, 220),
    (700, 310),
    (660, 610),
    (512, 760),
    (364, 610),
    (324, 310),
]
draw.polygon(shield, fill=(18, 22, 36, 255), outline=(110, 255, 220, 255))
draw.line(shield + [shield[0]], fill=(110, 255, 220, 255), width=8)

# Inner face silhouette
draw.ellipse((392, 320, 632, 560), fill=(24, 28, 44, 255), outline=(196, 110, 255, 255), width=6)
draw.rounded_rectangle((426, 510, 598, 680), radius=70, fill=(24, 28, 44, 255), outline=(196, 110, 255, 255), width=6)

# Visor
draw.rounded_rectangle((418, 398, 606, 458), radius=24, fill=(0, 245, 215, 235), outline=(220, 255, 255, 255), width=4)
draw.line((455, 430, 570, 430), fill=(235, 255, 255, 255), width=4)

# Accent nodes
for cx, cy, r, color in [
    (360, 300, 14, (0, 255, 210, 255)),
    (664, 300, 14, (196, 110, 255, 255)),
    (328, 620, 12, (196, 110, 255, 255)),
    (696, 620, 12, (0, 255, 210, 255)),
]:
    draw.ellipse((cx - r, cy - r, cx + r, cy + r), fill=color)

# Monogram
draw.rounded_rectangle((430, 792, 594, 860), radius=18, fill=(12, 16, 32, 220), outline=(110, 255, 220, 180), width=3)
draw.text((467, 808), "GO", fill=(220, 255, 250, 255))

# Border
draw.rounded_rectangle((36, 36, 988, 988), radius=56, outline=(120, 70, 255, 140), width=6)

img.save("github_profile_pic.png")
print("saved github_profile_pic.png")
