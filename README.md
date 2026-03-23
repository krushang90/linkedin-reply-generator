# LinkedIn Reply Generator — Yashvi

A web app that generates personalized LinkedIn replies for **Yashvi Global** and **Yashvi Konnect** posts, powered by Claude AI.

## Setup

```bash
npm install
export ANTHROPIC_API_KEY=your_api_key_here
npm start
```

Then open `http://localhost:3000`

## How it works

1. Select which company the post/comment is for (Yashvi Global or Yashvi Konnect)
2. Paste the LinkedIn comment or message you received
3. Optionally add context about the person
4. Click **Generate Reply** — the reply streams in real time
5. Copy and paste it directly into LinkedIn

## Features

- Streams replies in real time
- Separate personas for Yashvi Global (360° digital marketing + software dev) and Yashvi Konnect (e-commerce focused)
- Replies are written to sound like a real person, not a corporate bot
- Soft CTA included in every reply to move conversations forward
- Ctrl+Enter / Cmd+Enter keyboard shortcut to generate
