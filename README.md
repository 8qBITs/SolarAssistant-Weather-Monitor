# SolarAssistant Weather Monitor (ARSO Slovenia)

A local Raspberry Pi web app that monitors **ARSO** (Slovenian Environment Agency) weather forecast for your region and automatically changes **SolarAssistant** inverter settings to charge batteries during cheap night electricity when tomorrow is expected to be a **bad PV day**.

Bad PV day triggers (configurable):
- **oblačno** (overcast) ✅ (important in winter)
- **dež** (rain)
- **sneg** (snow)
- **megla** (fog)

The app also provides a modern web UI for:
- manual switching between Day/Night modes
- viewing tomorrow’s ARSO forecast blocks (parsed)
- viewing SolarAssistant MQTT **response messages**
- viewing audit logs of actions
- enabling/disabling automation

---

## How it works

### Weather logic (ARSO)
The app downloads the ARSO XML forecast for your region (example: **Savinjska**) and checks **tomorrow** entries (`<metData>`) for:
- `nn_icon == overcast` or `nn_shortText` contains “oblačno”
- rain/snow/fog signals from ARSO fields and Slovene keywords

If any trigger matches → `bad_pv_tomorrow = True`.

### Automation logic (SolarAssistant)
If `bad_pv_tomorrow = True` and automation is enabled:

- **23:00 (cheap start)**  
  - sets **charger source priority** to **Solar and utility simultaneously**
  - sets **max grid charge current** to **40A** (configurable)
- **06:00 (cheap end)**  
  - sets **charger source priority** back to **Solar only**
  - sets **max grid charge current** back to **0A** (configurable)

All commands are applied to:
- `inverter_1`
- `inverter_2`
- `inverter_3`

> This matches a 3-phase setup with one inverter per phase.

---

## Requirements

- Raspberry Pi (or any Linux box)
- Python 3.10+ (3.12 works)
- SolarAssistant with MQTT enabled
- Network access to SolarAssistant MQTT broker
- ARSO XML access (public endpoint)

---

## Install

```bash
git clone <your-repo>
cd solar-pi-control

python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
