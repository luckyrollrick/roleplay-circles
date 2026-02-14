# Roleplay Circles

**Status:** Idea / Planning  
**Created:** 2026-02-13  
**Origin:** Spin-off from Sales Call AI Assistant concept

---

## The Problem

Sales reps want to roleplay but can't commit to fixed times:
- Scheduled roleplay gets bumped by real calls (always takes priority)
- Asking "who wants to roleplay now?" in Slack/WhatsApp doesn't work — people are busy at that exact moment
- There's a mismatch between desire to practice and ability to coordinate

**Validated by:** Ricky's own experience with his sales team Slack and a community WhatsApp group. People want to practice, coordination is the blocker.

---

## The Solution

**Availability-first matching, not scheduling-first.**

### Core Features
1. **Calendar sync** — Watches for gaps in your calendar
2. **Auto-availability windows** — Set hours when you're open for roleplay if calendar is clear (e.g., 10am-6pm)
3. **No-show trigger** — 10 min into a scheduled call, app asks "did they show?" → if no, flips you to available instantly
4. **Circle notifications** — When someone becomes available, circle gets pinged
5. **Quick matching** — Jump into roleplay while you're already warmed up

### The Insight
The no-show trigger is the unique hook. You're already in call mode, adrenaline up, prospect ghosted — perfect moment to rep instead of scrolling.

---

## Go-To-Market Strategy

### Phase 1: Internal Testing
- Build for Ricky's sales team (5 people)
- Work out kinks, track performance
- **Metrics to track:**
  - Show rate to roleplay when pinged
  - Session length (5 min vs 30 min)
  - Repeat usage (habit or novelty?)
  - Self-reported improvement on real calls

### Phase 2: Roleplay Roulette (Free)
- Public website, random matching with strangers
- Low commitment, "try it for fun" framing
- Viral top-of-funnel play
- "Sales training" sounds like homework; "Roleplay Roulette" sounds like a game. People share games.

### Phase 3: Private Circles (Paid)
- Team/community-based circles
- Full features: calendar sync, no-show triggers, availability windows
- Performance tracking over time
- Upsell from roulette users who want it with their actual team

---

## Funnel

```
Free: Roleplay Roulette (strangers, random, viral)
            ↓
Paid: Private Circles (team, calendar sync, tracking)
```

---

## Open Questions

- [ ] What's the minimum circle size for reliable matching?
- [ ] Mobile app vs. web app vs. Slack/Discord bot?
- [ ] How to handle time zones in circles?
- [ ] Voice call built-in or redirect to Zoom/phone?
- [ ] Gamification? Leaderboards? Streak tracking?

---

## Competitive Landscape

*To research:*
- Do Gong, Chorus, or sales training platforms have spontaneous roleplay matching?
- Existing "find a practice partner" apps in other domains (language learning, etc.)

---

## Quick Start (MVP)

### 1. Run the app
```bash
cd projects/roleplay-circles
./run.sh
```

### 2. Open in browser
Go to: http://localhost:5050

### 3. Configure your settings
1. Click ⚙️ Settings
2. Paste your Google Calendar ICS URL
   - Get it from: Google Calendar → Settings → [Your calendar] → Integrate calendar → Secret address in iCal format
3. Add your Zoom link
4. Set your availability hours
5. Save

### 4. Get teammate's ICS URL
Have them send you their ICS URL and add it to `config.json`

---

## Next Steps

1. [x] Design MVP feature set for team testing
2. [x] Decide on tech stack (web app? mobile? bot?)
3. [x] Build v0.1 for Ricky's team
4. [ ] Run 30-60 day pilot, collect metrics
5. [ ] Decide go/no-go on Roulette launch

---

## Notes

*Add ongoing thoughts, learnings, pivots here.*
