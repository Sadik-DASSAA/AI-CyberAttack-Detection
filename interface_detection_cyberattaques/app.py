from __future__ import annotations

# STYLE BUILD: SOC-UI-STABILITY-RESPONSIVE-FIX-20260808

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from html import escape
from io import BytesIO
import os
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import requests
import streamlit as st


API_URL = os.getenv("API_URL", "http://127.0.0.1:8000").rstrip("/")
APP_NAME = "Supervision des cyberattaques"
API_TIMEOUT = (2.5, 8.0)

PAGE_DASHBOARD = "Tableau de bord opérationnel"
PAGE_DETECTION = "Opérations de détection"
PAGE_PROFILE = "Gestion du destinataire"
PAGE_NOTIFICATIONS = "Centre de traitement des alertes"
PAGE_HISTORY = "Registre des incidents"

NAVIGATION_LABELS = {
    PAGE_DASHBOARD: "Tableau de bord",
    PAGE_DETECTION: "Détection",
    PAGE_NOTIFICATIONS: "Alertes",
    PAGE_HISTORY: "Historique",
    PAGE_PROFILE: "Destinataire",
}

DISPLAY_COLUMN_NAMES = {
    "date": "Horodatage",
    "source": "Moteur de détection",
    "fichier": "Élément analysé",
    "filename": "Élément analysé",
    "classe": "Type de menace",
    "signature": "Signature IDS",
    "categorie": "Catégorie IDS",
    "nombre": "Occurrences",
    "pourcentage": "Part des flux (%)",
    "gravite": "Niveau de sévérité",
    "action_recommandee": "Mesure de réponse recommandée",
    "ip_source": "Adresse IP source",
    "ip_destination": "Adresse IP de destination",
    "protocole": "Protocole réseau",
    "statut": "Statut de traitement",
    "notification_email": "État de notification",
    "erreur_notification_email": "Diagnostic de notification",
    "details": "Détails techniques",
    "mode_analyse": "Moteur d'analyse",
    "canal": "Canal de diffusion",
    "erreur": "Diagnostic",
}

DISPLAY_VALUES = {
    "CSV": "Moteur IA",
    "Suricata": "IDS Suricata",
    "Critique": "Critique",
    "Elevee": "Élevée",
    "Moyenne": "Moyenne",
    "Faible": "Faible",
    "Non traitee": "À traiter",
    "Traitee": "Traité",
    "Envoyee": "Transmis",
    "Envoye": "Transmis",
    "Echec": "Échec",
    "Maitrise": "Maîtrisé",
    "Eleve": "Élevé",
    "Modere": "Modéré",
    "Operationnel": "Opérationnel",
    "Operationnelle": "Opérationnelle",
    "Degrade": "Dégradé",
}


st.set_page_config(
    page_title=APP_NAME,
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Masque les controles Streamlit "Deploy" et le menu a trois points.
st.set_option("client.toolbarMode", "minimal")

st.markdown(
"""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap');

        :root {
            --soc-bg-0: #030712;
            --soc-bg-1: #071225;
            --soc-surface: rgba(10, 24, 47, 0.68);
            --soc-surface-strong: rgba(13, 31, 58, 0.88);
            --soc-surface-soft: rgba(16, 38, 67, 0.48);
            --soc-border: rgba(86, 222, 255, 0.24);
            --soc-border-strong: rgba(86, 222, 255, 0.52);
            --soc-text: #f4f8ff;
            --soc-muted: #a9b7ce;
            --soc-muted-2: #7890ad;
            --soc-cyan: #39e7ff;
            --soc-cyan-strong: #00c8ff;
            --soc-violet: #8a5cff;
            --soc-violet-strong: #6d3df5;
            --soc-success: #30f2a2;
            --soc-warning: #ffc857;
            --soc-danger: #ff4f91;
            --soc-shadow: 0 18px 48px rgba(0, 0, 0, 0.34);
            --soc-glow: 0 0 0 1px rgba(57, 231, 255, 0.08), 0 0 28px rgba(57, 231, 255, 0.10);
        }

        html, body, [class*="css"] {
            font-family: "IBM Plex Sans", "Segoe UI", Arial, sans-serif;
        }

        html, body {
            color-scheme: dark;
            background: var(--soc-bg-0);
        }

        /*
         * Le fond et la grille sont appliqués directement à .stApp.
         * Aucun pseudo-élément ni z-index négatif : cela évite que le contenu
         * Streamlit disparaisse derrière un calque sombre selon le navigateur.
         */
        .stApp {
            color: var(--soc-text);
            background-color: var(--soc-bg-0);
            background-image:
                radial-gradient(circle at 12% 8%, rgba(0, 200, 255, 0.18), transparent 31rem),
                radial-gradient(circle at 88% 18%, rgba(138, 92, 255, 0.19), transparent 34rem),
                radial-gradient(circle at 48% 86%, rgba(0, 217, 255, 0.08), transparent 40rem),
                linear-gradient(rgba(57, 231, 255, 0.025) 1px, transparent 1px),
                linear-gradient(90deg, rgba(57, 231, 255, 0.025) 1px, transparent 1px),
                linear-gradient(145deg, var(--soc-bg-0) 0%, #061124 48%, #090d1e 100%);
            background-size:
                auto,
                auto,
                auto,
                58px 58px,
                58px 58px,
                auto;
            background-attachment: fixed;
        }

        /* Rend explicitement visibles les conteneurs principaux de Streamlit. */
        [data-testid="stAppViewContainer"],
        [data-testid="stMain"],
        section.main,
        .main,
        .block-container {
            position: relative;
            z-index: 1;
            visibility: visible !important;
            opacity: 1 !important;
        }

        [data-testid="stAppViewContainer"],
        [data-testid="stMain"],
        section.main,
        .main {
            background: transparent !important;
        }

        [data-testid="stSidebar"] {
            z-index: 20;
            transition: width .24s ease, min-width .24s ease, max-width .24s ease, transform .24s ease !important;
        }

        [data-testid="stHeader"] {
            background: rgba(3, 7, 18, 0.48);
            backdrop-filter: blur(16px);
            border-bottom: 1px solid rgba(86, 222, 255, 0.10);
        }

        [data-testid="stDecoration"],
        #MainMenu,
        [data-testid="stMainMenu"],
        [data-testid="stAppDeployButton"],
        .stDeployButton {
            display: none !important;
        }

        [data-testid="stToolbar"],
        [data-testid="collapsedControl"],
        [data-testid="stSidebarCollapsedControl"],
        [data-testid="stExpandSidebarButton"],
        [data-testid="stSidebarCollapseButton"] {
            display: flex !important;
            visibility: visible !important;
            opacity: 1 !important;
            z-index: 1000000 !important;
        }

        [data-testid="collapsedControl"] button,
        [data-testid="stSidebarCollapsedControl"] button,
        [data-testid="stExpandSidebarButton"] button,
        [data-testid="stSidebarCollapseButton"] button {
            color: transparent !important;
            font-size: 0 !important;
            border: 1px solid var(--soc-border-strong) !important;
            border-radius: 11px !important;
            background: rgba(8, 20, 40, 0.86) !important;
            box-shadow: 0 0 20px rgba(57, 231, 255, 0.15) !important;
            backdrop-filter: blur(14px);
            position: relative;
        }

        /* Masque le nom interne de l'icône Material (ex. keyboard_double_arrow_left). */
        [data-testid="collapsedControl"] button span,
        [data-testid="stSidebarCollapsedControl"] button span,
        [data-testid="stExpandSidebarButton"] button span,
        [data-testid="stSidebarCollapseButton"] button span,
        [data-testid="collapsedControl"] button svg,
        [data-testid="stSidebarCollapsedControl"] button svg,
        [data-testid="stExpandSidebarButton"] button svg,
        [data-testid="stSidebarCollapseButton"] button svg {
            display: none !important;
        }

        [data-testid="stSidebarCollapseButton"] button::before {
            content: "‹";
        }

        [data-testid="collapsedControl"] button::before,
        [data-testid="stSidebarCollapsedControl"] button::before,
        [data-testid="stExpandSidebarButton"] button::before {
            content: "›";
        }

        [data-testid="collapsedControl"] button::before,
        [data-testid="stSidebarCollapsedControl"] button::before,
        [data-testid="stExpandSidebarButton"] button::before,
        [data-testid="stSidebarCollapseButton"] button::before {
            position: absolute;
            inset: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--soc-cyan);
            font-family: "JetBrains Mono", monospace;
            font-size: 24px;
            font-weight: 700;
            line-height: 1;
        }

        .block-container {
            max-width: 1580px;
            padding-top: 1.8rem;
            padding-bottom: 3.2rem;
        }

        [data-testid="stSidebar"] {
            background:
                radial-gradient(circle at 30% 4%, rgba(0, 200, 255, 0.17), transparent 16rem),
                linear-gradient(180deg, rgba(3, 11, 27, 0.98) 0%, rgba(7, 17, 37, 0.98) 100%);
            border-right: 1px solid rgba(86, 222, 255, 0.18);
            box-shadow: 20px 0 50px rgba(0, 0, 0, 0.24);
        }

        [data-testid="stSidebar"] * {
            font-family: "IBM Plex Sans", "Segoe UI", Arial, sans-serif;
        }

        [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p,
        [data-testid="stSidebar"] label,
        [data-testid="stSidebar"] span {
            color: #dceaff;
        }

        [data-testid="stSidebar"] [role="radiogroup"] label {
            position: relative;
            overflow: hidden;
            border: 1px solid transparent;
            border-radius: 11px;
            padding: 0.62rem 0.72rem;
            margin-bottom: 0.34rem;
            transition: transform 0.22s ease, border-color 0.22s ease, background 0.22s ease, box-shadow 0.22s ease;
        }

        [data-testid="stSidebar"] [role="radiogroup"] label:hover {
            transform: translateX(3px);
            border-color: rgba(57, 231, 255, 0.25);
            background: rgba(57, 231, 255, 0.075);
            box-shadow: 0 0 20px rgba(57, 231, 255, 0.08);
        }

        [data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) {
            border-color: rgba(86, 222, 255, 0.42);
            background: linear-gradient(135deg, rgba(0, 200, 255, 0.22), rgba(138, 92, 255, 0.22));
            box-shadow: inset 0 0 18px rgba(57, 231, 255, 0.08), 0 0 24px rgba(57, 231, 255, 0.13);
        }

        .soc-brand {
            padding: 0.65rem 0.2rem 1.35rem;
            border-bottom: 1px solid rgba(86, 222, 255, 0.16);
            margin-bottom: 1.15rem;
        }

        .soc-brand__mark {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 42px;
            height: 42px;
            margin-right: 0.68rem;
            border-radius: 12px;
            color: #ffffff;
            font-family: "JetBrains Mono", monospace;
            font-weight: 800;
            background: linear-gradient(135deg, var(--soc-cyan-strong), var(--soc-violet));
            box-shadow: 0 0 30px rgba(57, 231, 255, 0.34), 0 0 42px rgba(138, 92, 255, 0.18);
        }

        .soc-brand__name,
        .soc-page-header h1,
        .soc-section-heading h2,
        .soc-module-card h3 {
            font-family: "Space Grotesk", "Segoe UI", sans-serif;
        }

        .soc-brand__name {
            color: #ffffff;
            display: block;
            font-size: 1.02rem;
            font-weight: 700;
            letter-spacing: 0.01em;
            line-height: 1.25;
        }

        .soc-brand__version,
        .soc-brand__descriptor,
        .soc-module-card__code,
        .soc-page-header__eyebrow,
        [data-testid="stMetricLabel"],
        .soc-status-card__label,
        .soc-live-caption,
        code, pre {
            font-family: "JetBrains Mono", Consolas, monospace !important;
        }

        .soc-brand__version {
            color: #8297b5;
            font-size: 0.68rem;
            margin: 0.58rem 0 0 3.42rem;
        }

        .soc-sidebar-footer {
            margin-top: 2rem;
            padding: 0.9rem;
            border: 1px solid rgba(86, 222, 255, 0.15);
            border-radius: 12px;
            color: #91a8c5;
            font-size: 0.76rem;
            line-height: 1.5;
            background: linear-gradient(145deg, rgba(10, 26, 49, 0.76), rgba(12, 23, 50, 0.52));
            box-shadow: inset 0 1px 0 rgba(255,255,255,.035);
            backdrop-filter: blur(16px);
        }

        .soc-page-header {
            margin-bottom: 1.55rem;
            padding: 1.25rem 1.35rem 1.35rem;
            border: 1px solid rgba(86, 222, 255, 0.17);
            border-radius: 18px;
            background: linear-gradient(145deg, rgba(12, 29, 55, 0.62), rgba(11, 20, 45, 0.42));
            box-shadow: var(--soc-shadow), inset 0 1px 0 rgba(255,255,255,.05);
            backdrop-filter: blur(18px) saturate(125%);
        }

        .soc-page-header__eyebrow {
            margin-bottom: 0.42rem;
            color: var(--soc-cyan);
            font-size: 0.72rem;
            font-weight: 700;
            letter-spacing: 0.14em;
            text-transform: uppercase;
            text-shadow: 0 0 18px rgba(57, 231, 255, 0.30);
        }

        .soc-page-header h1 {
            margin: 0;
            color: var(--soc-text);
            font-size: clamp(1.85rem, 2.6vw, 2.55rem);
            font-weight: 700;
            letter-spacing: -0.035em;
            line-height: 1.12;
        }

        .soc-page-header p {
            max-width: 980px;
            margin: 0.65rem 0 0;
            color: var(--soc-muted);
            font-size: 0.98rem;
            line-height: 1.58;
        }

        .soc-section-heading {
            margin: 1.65rem 0 0.82rem;
        }

        .soc-section-heading h2 {
            margin: 0;
            color: var(--soc-text);
            font-size: 1.11rem;
            font-weight: 700;
            letter-spacing: -0.012em;
        }

        .soc-section-heading h2::before {
            content: "";
            display: inline-block;
            width: 5px;
            height: 1.05rem;
            margin-right: 0.58rem;
            border-radius: 999px;
            vertical-align: -0.10rem;
            background: linear-gradient(180deg, var(--soc-cyan), var(--soc-violet));
            box-shadow: 0 0 14px rgba(57, 231, 255, 0.44);
        }

        .soc-section-heading p {
            margin: 0.28rem 0 0;
            color: var(--soc-muted);
            font-size: 0.86rem;
        }

        [data-testid="stMetric"],
        [data-testid="stVerticalBlockBorderWrapper"],
        .soc-module-card,
        .soc-status-card {
            border: 1px solid var(--soc-border) !important;
            background: linear-gradient(145deg, rgba(13, 31, 58, 0.78), rgba(9, 20, 43, 0.60)) !important;
            box-shadow: var(--soc-glow), var(--soc-shadow);
            backdrop-filter: blur(18px) saturate(125%);
            transition: transform 0.22s ease, border-color 0.22s ease, box-shadow 0.22s ease;
        }

        [data-testid="stMetric"]:hover,
        [data-testid="stVerticalBlockBorderWrapper"]:hover,
        .soc-module-card:hover,
        .soc-status-card:hover {
            transform: translateY(-3px);
            border-color: var(--soc-border-strong) !important;
            box-shadow: 0 22px 54px rgba(0,0,0,.40), 0 0 30px rgba(57, 231, 255, 0.13), 0 0 42px rgba(138, 92, 255, 0.08);
        }

        [data-testid="stMetric"] {
            min-height: 118px;
            padding: 1rem 1.08rem;
            border-radius: 15px;
        }

        [data-testid="stMetricLabel"] {
            color: var(--soc-muted) !important;
            font-size: 0.76rem;
            font-weight: 600;
            letter-spacing: 0.02em;
        }

        [data-testid="stMetricValue"] {
            color: #ffffff !important;
            font-family: "Space Grotesk", "IBM Plex Sans", sans-serif !important;
            font-size: 1.76rem;
            font-weight: 700;
            text-shadow: 0 0 24px rgba(57, 231, 255, 0.10);
        }

        [data-testid="stVerticalBlockBorderWrapper"] {
            border-radius: 16px !important;
            overflow: hidden;
        }

        .soc-module-card {
            min-height: 158px;
            padding: 1.18rem;
            border-radius: 15px;
        }

        .soc-module-card__code {
            color: var(--soc-cyan);
            font-size: 0.68rem;
            font-weight: 700;
            letter-spacing: 0.10em;
        }

        .soc-module-card h3 {
            margin: 0.48rem 0 0.42rem;
            color: var(--soc-text);
            font-size: 1.02rem;
        }

        .soc-module-card p {
            margin: 0;
            color: var(--soc-muted);
            font-size: 0.85rem;
            line-height: 1.52;
        }

        .soc-status-card {
            min-height: 132px;
            padding: 1rem 1.05rem;
            border-radius: 15px;
        }

        .soc-status-card__label {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            color: var(--soc-muted);
            font-size: 0.72rem;
            font-weight: 600;
        }

        @keyframes socPulseGreen {
            0%, 100% { box-shadow: 0 0 0 0 rgba(48, 242, 162, .42), 0 0 12px rgba(48, 242, 162, .55); }
            50% { box-shadow: 0 0 0 7px rgba(48, 242, 162, 0), 0 0 22px rgba(48, 242, 162, .85); }
        }

        @keyframes socPulseAmber {
            0%, 100% { box-shadow: 0 0 0 0 rgba(255, 200, 87, .42), 0 0 12px rgba(255, 200, 87, .55); }
            50% { box-shadow: 0 0 0 7px rgba(255, 200, 87, 0), 0 0 22px rgba(255, 200, 87, .85); }
        }

        @keyframes socPulsePink {
            0%, 100% { box-shadow: 0 0 0 0 rgba(255, 79, 145, .42), 0 0 12px rgba(255, 79, 145, .55); }
            50% { box-shadow: 0 0 0 7px rgba(255, 79, 145, 0), 0 0 22px rgba(255, 79, 145, .85); }
        }

        .soc-status-card__dot,
        .soc-live-caption__pulse {
            width: 9px;
            height: 9px;
            border-radius: 999px;
            background: #7f91aa;
        }

        .soc-status-card--success .soc-status-card__dot,
        .soc-live-caption__pulse {
            background: var(--soc-success);
            animation: socPulseGreen 1.8s infinite ease-in-out;
        }

        .soc-status-card--warning .soc-status-card__dot {
            background: var(--soc-warning);
            animation: socPulseAmber 1.8s infinite ease-in-out;
        }

        .soc-status-card--danger .soc-status-card__dot {
            background: var(--soc-danger);
            animation: socPulsePink 1.65s infinite ease-in-out;
        }

        .soc-status-card__value {
            margin-top: 0.7rem;
            color: var(--soc-text);
            font-family: "Space Grotesk", sans-serif;
            font-size: 1.1rem;
            font-weight: 700;
        }

        .soc-status-card__detail {
            margin-top: 0.34rem;
            color: var(--soc-muted);
            font-size: 0.73rem;
            line-height: 1.4;
        }

        .soc-live-caption {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin: 0.25rem 0 0.82rem;
            color: var(--soc-muted);
            font-size: 0.70rem;
        }

        .soc-gauge-heading {
            padding: 0.92rem 1rem 0.10rem;
            text-align: center;
        }

        .soc-gauge-heading__label {
            color: var(--soc-muted);
            font-family: "JetBrains Mono", monospace;
            font-size: 0.67rem;
            font-weight: 600;
            letter-spacing: 0.095em;
            text-transform: uppercase;
        }

        .soc-gauge-heading__value {
            margin-top: 0.26rem;
            font-family: "Space Grotesk", sans-serif;
            font-size: 1.24rem;
            font-weight: 700;
            line-height: 1.15;
        }

        div[data-baseweb="tab-list"] {
            gap: 0.35rem;
            padding: 0.34rem;
            border: 1px solid var(--soc-border);
            border-radius: 13px;
            background: rgba(8, 20, 42, 0.72);
            backdrop-filter: blur(14px);
        }

        button[data-baseweb="tab"] {
            min-height: 44px;
            border-radius: 10px;
            color: var(--soc-muted);
            font-weight: 650;
        }

        button[data-baseweb="tab"][aria-selected="true"] {
            color: #ffffff;
            background: linear-gradient(135deg, var(--soc-cyan-strong), var(--soc-violet));
            box-shadow: 0 0 24px rgba(57, 231, 255, 0.22), 0 0 30px rgba(138, 92, 255, 0.12);
        }

        .stButton > button,
        .stDownloadButton > button,
        [data-testid="stFormSubmitButton"] > button {
            min-height: 43px;
            border: 1px solid rgba(123, 226, 255, 0.56);
            border-radius: 11px;
            color: #ffffff;
            font-family: "Space Grotesk", sans-serif;
            font-weight: 700;
            background: linear-gradient(135deg, var(--soc-cyan-strong), var(--soc-violet));
            box-shadow: 0 0 22px rgba(57, 231, 255, 0.18), 0 0 28px rgba(138, 92, 255, 0.10);
            transition: transform .18s ease, filter .18s ease, box-shadow .18s ease;
        }

        .stButton > button:hover,
        .stDownloadButton > button:hover,
        [data-testid="stFormSubmitButton"] > button:hover {
            color: #ffffff;
            transform: translateY(-2px);
            filter: saturate(1.12) brightness(1.08);
            box-shadow: 0 0 30px rgba(57, 231, 255, 0.30), 0 0 38px rgba(138, 92, 255, 0.18);
        }

        [data-testid="stFileUploaderDropzone"],
        [data-baseweb="input"] > div,
        [data-baseweb="select"] > div,
        textarea {
            border: 1px solid var(--soc-border) !important;
            border-radius: 11px !important;
            color: var(--soc-text) !important;
            background: rgba(7, 18, 38, 0.78) !important;
            box-shadow: inset 0 1px 0 rgba(255,255,255,.03);
        }

        [data-baseweb="select"] span,
        [data-baseweb="input"] input,
        textarea,
        [data-testid="stFileUploaderDropzone"] * {
            color: var(--soc-text) !important;
        }

        [data-testid="stDataFrame"] {
            overflow: hidden;
            border: 1px solid var(--soc-border);
            border-radius: 13px;
            background: rgba(7, 18, 38, 0.80);
            box-shadow: var(--soc-glow);
        }

        [data-testid="stAlert"] {
            border: 1px solid rgba(86, 222, 255, 0.20);
            border-radius: 12px;
            color: var(--soc-text);
            background: rgba(10, 26, 51, 0.74);
            backdrop-filter: blur(14px);
        }

        details {
            border: 1px solid var(--soc-border) !important;
            border-radius: 12px !important;
            color: var(--soc-text) !important;
            background: rgba(7, 18, 38, 0.78) !important;
        }

        h1, h2, h3, h4, h5, h6,
        [data-testid="stMarkdownContainer"] strong {
            color: var(--soc-text);
        }

        p, label, .stCaption, [data-testid="stCaptionContainer"] {
            color: var(--soc-muted);
        }

        a { color: var(--soc-cyan); }
        hr { border-color: rgba(86, 222, 255, 0.16); }

        @media (max-width: 1100px) {
            .block-container { padding-left: 1rem; padding-right: 1rem; }
            [data-testid="stMetric"] { min-height: 108px; }
            .soc-page-header { padding: 1.05rem; }
        }

        @media (max-width: 760px) {
            .block-container { padding-top: 1rem; }
            .soc-page-header h1 { font-size: 1.72rem; }
            .soc-page-header p { font-size: 0.90rem; }
            [data-testid="stMetricValue"] { font-size: 1.48rem; }
            .soc-status-card { min-height: 118px; }
            .soc-gauge-heading__value { font-size: 1.08rem; }
        }

        @media (prefers-reduced-motion: reduce) {
            *, *::before, *::after {
                animation-duration: 0.001ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: 0.001ms !important;
            }
        }
    </style>
    """,
    unsafe_allow_html=True,
)

# Couche de finition visuelle uniquement : aucun appel API ni traitement métier modifié.
st.markdown(
    """
    <style>
        :root {
            --soc-sidebar-width: 292px;
            --soc-panel: rgba(7, 20, 42, 0.78);
            --soc-panel-hover: rgba(11, 30, 58, 0.92);
            --soc-line: rgba(92, 228, 255, 0.20);
            --soc-line-hot: rgba(92, 228, 255, 0.62);
        }

        /* ===== Structure générale ===== */
        .block-container {
            max-width: 1640px;
            padding: 1.55rem 2rem 4rem;
        }

        /* Largeur personnalisée uniquement lorsque la barre est ouverte. */
        [data-testid="stSidebar"][aria-expanded="true"] {
            width: var(--soc-sidebar-width) !important;
            min-width: var(--soc-sidebar-width) !important;
            transform: translateX(0) !important;
        }

        /* Laisse Streamlit réduire réellement la barre latérale. */
        [data-testid="stSidebar"][aria-expanded="false"] {
            width: 0 !important;
            min-width: 0 !important;
            max-width: 0 !important;
            transform: translateX(-100%) !important;
            overflow: hidden !important;
            border-right: 0 !important;
            box-shadow: none !important;
        }

        [data-testid="stSidebar"][aria-expanded="false"] > div:first-child,
        [data-testid="stSidebar"][aria-expanded="false"] [data-testid="stSidebarUserContent"] {
            width: 0 !important;
            min-width: 0 !important;
            padding-left: 0 !important;
            padding-right: 0 !important;
            overflow: hidden !important;
        }

        [data-testid="stSidebar"] > div:first-child {
            padding: 1rem 0.85rem 1.2rem;
        }

        [data-testid="stSidebarUserContent"] {
            padding-top: 0.2rem;
        }

        /* ===== Identité visuelle / logo ===== */
        .soc-brand {
            display: grid;
            grid-template-columns: 54px minmax(0, 1fr);
            gap: 0.82rem;
            align-items: center;
            margin: 0 0 1rem;
            padding: 0.78rem 0.72rem 1.15rem;
            border-bottom: 1px solid rgba(92, 228, 255, 0.14);
        }

        .soc-brand__emblem {
            position: relative;
            display: grid;
            place-items: center;
            width: 52px;
            height: 52px;
            border: 1px solid rgba(92, 228, 255, 0.48);
            border-radius: 16px;
            background:
                radial-gradient(circle at 30% 25%, rgba(57, 231, 255, 0.28), transparent 52%),
                linear-gradient(145deg, rgba(10, 42, 72, 0.96), rgba(31, 18, 75, 0.94));
            box-shadow:
                inset 0 1px 0 rgba(255,255,255,.10),
                0 0 0 1px rgba(138, 92, 255, 0.12),
                0 0 26px rgba(57, 231, 255, 0.20),
                0 0 42px rgba(138, 92, 255, 0.12);
            overflow: hidden;
        }

        .soc-brand__emblem::after {
            content: "";
            position: absolute;
            inset: -60% 42% -60% -18%;
            transform: rotate(22deg);
            background: linear-gradient(90deg, transparent, rgba(255,255,255,.22), transparent);
            animation: socLogoScan 5.2s infinite ease-in-out;
        }

        @keyframes socLogoScan {
            0%, 58% { transform: translateX(-170%) rotate(22deg); opacity: 0; }
            66% { opacity: 1; }
            88%, 100% { transform: translateX(260%) rotate(22deg); opacity: 0; }
        }

        .soc-brand__emblem svg {
            width: 34px;
            height: 34px;
            filter: drop-shadow(0 0 8px rgba(57, 231, 255, 0.48));
        }

        .soc-brand__copy { min-width: 0; }

        .soc-brand__name {
            display: block;
            margin: 0;
            color: #f7fbff;
            font-family: "Space Grotesk", sans-serif;
            font-size: 0.98rem;
            font-weight: 700;
            line-height: 1.15;
            letter-spacing: 0.055em;
        }

        .soc-brand__descriptor {
            display: block;
            margin-top: 0.26rem;
            color: #8fa9c8;
            font-family: "IBM Plex Sans", sans-serif;
            font-size: 0.70rem;
            line-height: 1.25;
        }

        .soc-brand__version {
            display: inline-flex;
            align-items: center;
            gap: 0.32rem;
            margin: 0.48rem 0 0;
            padding: 0.20rem 0.42rem;
            border: 1px solid rgba(57, 231, 255, 0.16);
            border-radius: 999px;
            color: #9cb3ce;
            font-size: 0.60rem;
            line-height: 1;
            background: rgba(3, 12, 27, 0.58);
        }

        .soc-brand__version::before {
            content: "";
            width: 5px;
            height: 5px;
            border-radius: 50%;
            background: var(--soc-success);
            box-shadow: 0 0 9px rgba(48, 242, 162, .85);
        }

        /* ===== Navigation latérale ===== */
        [data-testid="stSidebar"] [data-testid="stRadio"] > label,
        [data-testid="stSidebar"] .stRadio > label {
            display: none !important;
        }

        [data-testid="stSidebar"] [role="radiogroup"] {
            display: flex;
            flex-direction: column;
            gap: 0.30rem;
            margin-top: 0.15rem;
        }

        [data-testid="stSidebar"] [role="radiogroup"] label {
            position: relative;
            display: grid !important;
            grid-template-columns: 36px minmax(0, 1fr) 12px;
            align-items: center;
            min-height: 48px;
            margin: 0;
            padding: 0.42rem 0.62rem 0.42rem 0.48rem;
            border: 1px solid transparent;
            border-radius: 13px;
            color: #b4c4da;
            background: transparent;
            cursor: pointer;
            overflow: hidden;
            transition: transform .18s ease, color .18s ease, border-color .18s ease, background .18s ease, box-shadow .18s ease;
        }

        /* Masque uniquement le cercle radio natif, sans masquer le texte du menu. */
        [data-testid="stSidebar"] [role="radiogroup"] label > div:first-child > div:first-child {
            display: none !important;
        }

        [data-testid="stSidebar"] [role="radiogroup"] label > div:first-child > div:last-child {
            min-width: 0 !important;
            margin: 0 !important;
        }

        [data-testid="stSidebar"] [role="radiogroup"] label input {
            position: absolute !important;
            opacity: 0 !important;
            pointer-events: none !important;
        }

        [data-testid="stSidebar"] [role="radiogroup"] label::before {
            display: grid;
            place-items: center;
            width: 31px;
            height: 31px;
            border: 1px solid rgba(118, 177, 218, 0.15);
            border-radius: 10px;
            color: #8ea8c5;
            font-family: "JetBrains Mono", monospace;
            font-size: 0.94rem;
            line-height: 1;
            background: rgba(7, 20, 41, 0.68);
            box-shadow: inset 0 1px 0 rgba(255,255,255,.035);
            transition: all .18s ease;
        }

        [data-testid="stSidebar"] [role="radiogroup"] label:nth-child(1)::before { content: "⌂"; }
        [data-testid="stSidebar"] [role="radiogroup"] label:nth-child(2)::before { content: "⌁"; }
        [data-testid="stSidebar"] [role="radiogroup"] label:nth-child(3)::before { content: "!"; }
        [data-testid="stSidebar"] [role="radiogroup"] label:nth-child(4)::before { content: "≡"; }
        [data-testid="stSidebar"] [role="radiogroup"] label:nth-child(5)::before { content: "◎"; }

        [data-testid="stSidebar"] [role="radiogroup"] label::after {
            content: "›";
            justify-self: end;
            color: #58738f;
            font-family: "JetBrains Mono", monospace;
            font-size: 1rem;
            opacity: 0;
            transform: translateX(-4px);
            transition: opacity .18s ease, transform .18s ease, color .18s ease;
        }

        [data-testid="stSidebar"] [role="radiogroup"] label span {
            color: inherit !important;
            font-family: "IBM Plex Sans", sans-serif !important;
            font-size: 0.83rem !important;
            font-weight: 600 !important;
            line-height: 1.22 !important;
            white-space: normal !important;
        }

        [data-testid="stSidebar"] [role="radiogroup"] label:hover {
            transform: translateX(2px);
            color: #eef8ff;
            border-color: rgba(57, 231, 255, 0.23);
            background: linear-gradient(90deg, rgba(57, 231, 255, 0.075), rgba(138, 92, 255, 0.035));
            box-shadow: 0 8px 22px rgba(0,0,0,.16);
        }

        [data-testid="stSidebar"] [role="radiogroup"] label:hover::before {
            color: var(--soc-cyan);
            border-color: rgba(57, 231, 255, 0.34);
            box-shadow: 0 0 16px rgba(57, 231, 255, 0.12);
        }

        [data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) {
            transform: none;
            color: #ffffff;
            border-color: rgba(78, 224, 255, 0.44);
            background:
                linear-gradient(110deg, rgba(0, 200, 255, 0.19), rgba(138, 92, 255, 0.16));
            box-shadow:
                inset 3px 0 0 var(--soc-cyan),
                inset 0 1px 0 rgba(255,255,255,.055),
                0 0 24px rgba(57, 231, 255, 0.09);
        }

        [data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked)::before {
            color: #ffffff;
            border-color: rgba(121, 236, 255, 0.60);
            background: linear-gradient(145deg, rgba(0, 200, 255, 0.30), rgba(138, 92, 255, 0.30));
            box-shadow: 0 0 18px rgba(57, 231, 255, 0.24);
        }

        [data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked)::after {
            color: var(--soc-cyan);
            opacity: 1;
            transform: translateX(0);
        }

        .soc-sidebar-footer {
            position: relative;
            margin: 1.35rem 0.15rem 0;
            padding: 0.78rem 0.82rem;
            border: 1px solid rgba(79, 218, 255, 0.18);
            border-radius: 13px;
            background: linear-gradient(145deg, rgba(8, 28, 51, 0.82), rgba(18, 18, 48, 0.72));
            box-shadow: inset 0 1px 0 rgba(255,255,255,.04);
        }

        .soc-sidebar-footer__status {
            display: flex;
            align-items: center;
            gap: 0.48rem;
            color: #d8e8f8;
            font-family: "Space Grotesk", sans-serif;
            font-size: 0.73rem;
            font-weight: 600;
        }

        .soc-sidebar-footer__status::before {
            content: "";
            width: 7px;
            height: 7px;
            border-radius: 50%;
            background: var(--soc-success);
            animation: socPulseGreen 1.8s infinite ease-in-out;
        }

        .soc-sidebar-footer__meta {
            margin-top: 0.36rem;
            color: #7f97b4;
            font-family: "JetBrains Mono", monospace;
            font-size: 0.58rem;
            line-height: 1.45;
        }

        /* ===== Hiérarchie des pages ===== */
        .soc-page-header {
            position: relative;
            overflow: hidden;
            padding: 1.35rem 1.5rem 1.45rem;
        }

        .soc-page-header::after {
            content: "";
            position: absolute;
            top: -110px;
            right: -60px;
            width: 270px;
            height: 210px;
            border: 1px solid rgba(57, 231, 255, .09);
            border-radius: 48%;
            background: radial-gradient(circle, rgba(57, 231, 255, .10), transparent 66%);
            pointer-events: none;
        }

        .soc-section-heading {
            margin-top: 1.75rem;
        }

        .soc-section-heading p {
            max-width: 920px;
            color: #8399b4;
            line-height: 1.45;
        }

        /* ===== Tableaux professionnels ===== */
        [data-testid="stDataFrame"] {
            position: relative;
            padding: 0.45rem;
            border: 1px solid rgba(83, 224, 255, 0.28) !important;
            border-radius: 16px !important;
            background:
                linear-gradient(145deg, rgba(8, 25, 49, 0.93), rgba(6, 17, 37, 0.90)) !important;
            box-shadow:
                inset 0 1px 0 rgba(255,255,255,.035),
                0 16px 38px rgba(0,0,0,.24),
                0 0 24px rgba(57,231,255,.055) !important;
        }

        [data-testid="stDataFrame"]::before {
            content: "DONNÉES OPÉRATIONNELLES";
            display: block;
            padding: 0.32rem 0.42rem 0.58rem;
            color: #7692b0;
            font-family: "JetBrains Mono", monospace;
            font-size: 0.56rem;
            font-weight: 600;
            letter-spacing: .12em;
        }

        [data-testid="stDataFrame"] [data-testid="stElementToolbar"] {
            top: 0.38rem !important;
            right: 0.45rem !important;
        }

        [data-testid="stDataFrame"] button {
            border: 1px solid rgba(57, 231, 255, 0.18) !important;
            border-radius: 8px !important;
            color: #a9c2dc !important;
            background: rgba(5, 17, 36, 0.86) !important;
        }

        [data-testid="stDataFrame"] [role="columnheader"] {
            color: #dff8ff !important;
            font-family: "JetBrains Mono", monospace !important;
            font-size: 0.68rem !important;
            font-weight: 700 !important;
            letter-spacing: .025em;
            background: rgba(13, 41, 69, 0.96) !important;
            border-bottom: 1px solid rgba(57, 231, 255, .32) !important;
        }

        [data-testid="stDataFrame"] [role="gridcell"] {
            color: #d3dfed !important;
            font-family: "IBM Plex Sans", sans-serif !important;
            border-color: rgba(105, 155, 194, 0.10) !important;
        }

        [data-testid="stDataFrame"] [role="row"]:hover [role="gridcell"] {
            background: rgba(57, 231, 255, .055) !important;
        }

        /* Barres de défilement */
        * {
            scrollbar-width: thin;
            scrollbar-color: rgba(57, 231, 255, .38) rgba(3, 12, 27, .5);
        }

        *::-webkit-scrollbar { width: 9px; height: 9px; }
        *::-webkit-scrollbar-track { background: rgba(3, 12, 27, .55); }
        *::-webkit-scrollbar-thumb {
            border: 2px solid rgba(3, 12, 27, .75);
            border-radius: 999px;
            background: linear-gradient(180deg, rgba(57,231,255,.52), rgba(138,92,255,.48));
        }

        /* ===== Contrôles et éléments secondaires ===== */
        [data-testid="stFileUploaderDropzone"] {
            min-height: 116px;
            border-style: dashed !important;
            border-width: 1px !important;
            background:
                radial-gradient(circle at 10% 20%, rgba(57, 231, 255, .08), transparent 48%),
                rgba(7, 19, 39, .76) !important;
        }

        [data-testid="stFileUploaderDropzone"]:hover {
            border-color: rgba(57, 231, 255, .62) !important;
            box-shadow: 0 0 26px rgba(57, 231, 255, .10);
        }

        /* Bouton d'importation : contraste renforcé sur fond sombre. */
        [data-testid="stFileUploaderDropzone"] button {
            min-width: 118px !important;
            min-height: 42px !important;
            padding: 0.62rem 1rem !important;
            border: 1px solid rgba(105, 238, 255, 0.76) !important;
            border-radius: 10px !important;
            color: #ffffff !important;
            background: linear-gradient(135deg, #00bfe8 0%, #7657f5 100%) !important;
            box-shadow:
                0 0 0 1px rgba(255, 255, 255, 0.05) inset,
                0 0 22px rgba(57, 231, 255, 0.18) !important;
            font-family: "Space Grotesk", sans-serif !important;
            font-size: 0.86rem !important;
            font-weight: 700 !important;
            opacity: 1 !important;
            filter: none !important;
            transition: transform .18s ease, box-shadow .18s ease, filter .18s ease;
        }

        [data-testid="stFileUploaderDropzone"] button *,
        [data-testid="stFileUploaderDropzone"] button p,
        [data-testid="stFileUploaderDropzone"] button span {
            color: #ffffff !important;
            opacity: 1 !important;
            font-weight: 700 !important;
        }

        [data-testid="stFileUploaderDropzone"] button svg {
            color: #ffffff !important;
            fill: currentColor !important;
            opacity: 1 !important;
        }

        [data-testid="stFileUploaderDropzone"] button:hover {
            transform: translateY(-1px);
            filter: brightness(1.10) saturate(1.10) !important;
            border-color: #9af4ff !important;
            box-shadow:
                0 0 0 1px rgba(255, 255, 255, 0.08) inset,
                0 0 30px rgba(57, 231, 255, 0.30),
                0 0 34px rgba(138, 92, 255, 0.18) !important;
        }

        [data-testid="stFileUploaderDropzone"] small,
        [data-testid="stFileUploaderDropzone"] [data-testid="stFileUploaderDropzoneInstructions"] {
            color: #d8e7f7 !important;
            opacity: 1 !important;
        }

        [data-testid="stFileUploaderFileName"],
        [data-testid="stFileUploaderFile"] span {
            max-width: 100%;
            overflow-wrap: anywhere;
            white-space: normal !important;
        }

        .soc-gauge-empty {
            display: grid;
            place-items: center;
            min-height: 184px;
            padding: 1rem;
            color: #a9b7ce;
            text-align: center;
            font-size: .82rem;
            line-height: 1.45;
        }

        [data-testid="stMetricLabel"] p,
        [data-testid="stMetricValue"] {
            overflow-wrap: anywhere;
            white-space: normal !important;
        }

        [data-testid="stAlert"] {
            border-left-width: 3px !important;
        }

        details summary {
            color: #d9e9f8 !important;
            font-family: "Space Grotesk", sans-serif;
            font-weight: 600;
        }

        [data-testid="stSelectbox"] label,
        [data-testid="stTextInput"] label,
        [data-testid="stFileUploader"] label,
        [data-testid="stTextArea"] label {
            color: #b9c9dc !important;
            font-size: .80rem !important;
            font-weight: 600 !important;
        }

        /* Le menu de réduction reste net et visible. */
        [data-testid="stSidebarCollapseButton"] button,
        [data-testid="stExpandSidebarButton"] button,
        [data-testid="collapsedControl"] button {
            width: 38px !important;
            height: 38px !important;
            border-radius: 12px !important;
        }

        @media (max-width: 900px) {
            .block-container { padding: 1rem 0.95rem 3rem; }
            [data-testid="stSidebar"][aria-expanded="true"] {
                width: min(88vw, var(--soc-sidebar-width)) !important;
                min-width: min(88vw, var(--soc-sidebar-width)) !important;
                max-width: min(88vw, var(--soc-sidebar-width)) !important;
            }
            .soc-brand { grid-template-columns: 46px minmax(0, 1fr); }
            .soc-brand__emblem { width: 44px; height: 44px; border-radius: 13px; }
            .soc-brand__emblem svg { width: 29px; height: 29px; }
            .soc-page-header { padding: 1rem 1.05rem 1.1rem; }
            .soc-page-header h1 { font-size: clamp(1.55rem, 8vw, 2rem); }
            [data-testid="stMetricValue"] { font-size: clamp(1.25rem, 6vw, 1.62rem); }
            div[data-baseweb="tab-list"] {
                overflow-x: auto;
                scrollbar-width: thin;
            }
            button[data-baseweb="tab"] {
                flex: 0 0 auto;
                min-width: max-content;
            }
        }

        @media (max-width: 520px) {
            .block-container { padding: .8rem .72rem 2.5rem; }
            .soc-page-header p { font-size: .84rem; line-height: 1.48; }
            .soc-section-heading h2 { font-size: 1rem; }
            [data-testid="stFileUploaderDropzone"] {
                min-height: 132px;
                padding: .7rem !important;
            }
            [data-testid="stFileUploaderDropzone"] button {
                width: 100% !important;
                min-width: 0 !important;
            }
        }
    </style>
    """,
    unsafe_allow_html=True,
)



def auth_headers() -> dict[str, str]:
    token = str(st.session_state.get("auth_token", "")).strip()
    return {"Authorization": f"Bearer {token}"} if token else {}


def api_error_detail(response: requests.Response) -> str:
    try:
        payload = response.json()
        detail = payload.get("detail", "") if isinstance(payload, dict) else ""
        if isinstance(detail, list):
            return " ".join(str(item.get("msg", item)) for item in detail)
        if detail:
            return str(detail)
    except (ValueError, TypeError):
        pass
    return f"Erreur HTTP {response.status_code}."


def get_api(
    endpoint: str,
    timeout: float | tuple[float, float] = API_TIMEOUT,
    request_headers: dict[str, str] | None = None,
) -> requests.Response:
    """Interroge l'API avec des en-têtes capturés dans le thread Streamlit."""
    return requests.get(
        f"{API_URL}{endpoint}",
        headers=auth_headers() if request_headers is None else request_headers,
        timeout=timeout,
    )


def get_api_batch(
    endpoints: dict[str, str],
) -> tuple[dict[str, requests.Response], dict[str, str]]:
    """Interroge les widgets du dashboard sans bloquer toute l'interface."""
    responses: dict[str, requests.Response] = {}
    erreurs: dict[str, str] = {}

    # Streamlit ne garantit pas l'accès à st.session_state depuis les threads
    # de travail. Le jeton est donc lu une seule fois dans le thread principal,
    # puis sa copie est transmise explicitement à chaque requête parallèle.
    request_headers = auth_headers()

    with ThreadPoolExecutor(max_workers=max(1, len(endpoints))) as executor:
        futures = {
            executor.submit(get_api, endpoint, API_TIMEOUT, request_headers): cle
            for cle, endpoint in endpoints.items()
        }
        for future in as_completed(futures):
            cle = futures[future]
            try:
                responses[cle] = future.result()
            except requests.RequestException as exc:
                erreurs[cle] = str(exc)

    return responses, erreurs


def post_status(historique_id: str, statut: str) -> requests.Response:
    return requests.post(
        f"{API_URL}/update-status",
        json={"historique_id": historique_id, "statut": statut},
        headers=auth_headers(),
        timeout=20,
    )


def post_reset_traffic_volume() -> requests.Response:
    return requests.post(
        f"{API_URL}/metrics/traffic/reset",
        headers=auth_headers(),
        timeout=20,
    )


@st.dialog("Réinitialiser le volume de trafic")
def render_traffic_reset_dialog() -> None:
    st.warning(
        "Cette action remet uniquement le compteur « Volume de trafic analysé » "
        "à zéro. Les alertes, attaques et incidents enregistrés seront conservés."
    )
    confirmation_col, annulation_col = st.columns(2)
    with confirmation_col:
        if st.button(
            "Confirmer",
            key="confirm_traffic_reset_action",
            type="primary",
            use_container_width=True,
        ):
            try:
                reset_response = post_reset_traffic_volume()
                if reset_response.status_code == 200:
                    st.session_state["traffic_reset_success"] = True
                    st.rerun()
                elif reset_response.status_code == 401:
                    effacer_session_authentifiee()
                    st.rerun()
                else:
                    st.error(api_error_detail(reset_response))
            except requests.RequestException as exc:
                st.error(f"API indisponible : {exc}")
    with annulation_col:
        if st.button(
            "Annuler",
            key="cancel_traffic_reset_action",
            use_container_width=True,
        ):
            st.rerun()


def request_profile_email_code(email: str) -> requests.Response:
    return requests.post(
        f"{API_URL}/profile/email/request-code",
        json={"email": email},
        headers=auth_headers(),
        timeout=25,
    )


def verify_profile_email_code(email: str, code: str) -> requests.Response:
    return requests.post(
        f"{API_URL}/profile/email/verify",
        json={"email": email, "code": code},
        headers=auth_headers(),
        timeout=20,
    )


def request_password_reset_code(email: str) -> requests.Response:
    return requests.post(
        f"{API_URL}/auth/password-reset/request-code",
        json={"email": email},
        timeout=25,
    )


def verify_password_reset_code(
    email: str,
    code: str,
    new_password: str,
) -> requests.Response:
    return requests.post(
        f"{API_URL}/auth/password-reset/verify",
        json={"email": email, "code": code, "new_password": new_password},
        timeout=25,
    )


def change_account_password(
    current_password: str,
    new_password: str,
) -> requests.Response:
    return requests.post(
        f"{API_URL}/profile/password/change",
        json={
            "current_password": current_password,
            "new_password": new_password,
        },
        headers=auth_headers(),
        timeout=25,
    )


def render_page_header(eyebrow: str, title: str, description: str) -> None:
    st.markdown(
        f"""
        <div class="soc-page-header">
            <div class="soc-page-header__eyebrow">{eyebrow}</div>
            <h1>{title}</h1>
            <p>{description}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_section_heading(title: str, description: str = "") -> None:
    description_html = f"<p>{description}</p>" if description else ""
    st.markdown(
        f"""
        <div class="soc-section-heading">
            <h2>{title}</h2>
            {description_html}
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_module_card(code: str, title: str, description: str) -> None:
    st.markdown(
        f"""
        <div class="soc-module-card">
            <div class="soc-module-card__code">{code}</div>
            <h3>{title}</h3>
            <p>{description}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def formater_nombre(value: object) -> str:
    if value is None:
        return "—"
    try:
        return f"{int(value):,}".replace(",", " ")
    except (TypeError, ValueError):
        return "—"


def render_status_card(
    label: str,
    value: str,
    detail: str,
    tone: str = "success",
) -> None:
    tone = tone if tone in {"success", "warning", "danger", "neutral"} else "neutral"
    st.markdown(
        f"""
        <div class="soc-status-card soc-status-card--{tone}">
            <div class="soc-status-card__label">
                <span class="soc-status-card__dot"></span>
                {escape(label)}
            </div>
            <div class="soc-status-card__value">{escape(value)}</div>
            <div class="soc-status-card__detail">{escape(detail)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def libelle_professionnel(value: object) -> object:
    if value is None:
        return value
    return DISPLAY_VALUES.get(str(value), value)


def dataframe_professionnel(dataframe: pd.DataFrame) -> pd.DataFrame:
    dataframe_affichage = dataframe.copy()
    for colonne in ["source", "gravite", "statut", "notification_email"]:
        if colonne in dataframe_affichage.columns:
            dataframe_affichage[colonne] = dataframe_affichage[colonne].map(
                libelle_professionnel
            )
    return dataframe_affichage.rename(columns=DISPLAY_COLUMN_NAMES)



def styliser_tableau_soc(dataframe: pd.DataFrame):
    """Applique uniquement une présentation SOC au tableau, sans changer ses données."""
    if dataframe is None or dataframe.empty:
        return dataframe

    def style_valeur(value: object) -> str:
        cle = _normaliser_cle(value)
        if cle == "CRITIQUE":
            return "color:#ff8ab8;font-weight:700;background-color:rgba(255,79,145,.13)"
        if cle in {"ELEVEE", "ELEVE"}:
            return "color:#ff9f86;font-weight:700;background-color:rgba(255,113,91,.11)"
        if cle in {"MOYENNE", "MODERE", "MODEREE"}:
            return "color:#ffd474;font-weight:700;background-color:rgba(255,200,87,.10)"
        if cle in {"FAIBLE", "TRAITE", "TRANSMIS", "OPERATIONNEL", "OPERATIONNELLE"}:
            return "color:#74f6bf;font-weight:650;background-color:rgba(48,242,162,.08)"
        if cle in {"A TRAITER", "NON TRAITEE", "EN ATTENTE"}:
            return "color:#ffd474;font-weight:650;background-color:rgba(255,200,87,.08)"
        if cle in {"ECHEC", "INDISPONIBLE", "DEGRADE"}:
            return "color:#ff8ab8;font-weight:700;background-color:rgba(255,79,145,.10)"
        return ""

    styler = dataframe.style
    if hasattr(styler, "map"):
        styler = styler.map(style_valeur)
    else:
        styler = styler.applymap(style_valeur)
    styler = styler.set_properties(
        **{
            "color": "#dbe7f4",
            "background-color": "rgba(7,18,38,.35)",
            "border-color": "rgba(100,154,194,.10)",
            "font-family": "IBM Plex Sans, sans-serif",
            "font-size": "12px",
        }
    )
    styler = styler.set_table_styles(
        [
            {
                "selector": "th",
                "props": [
                    ("background-color", "#0d2945"),
                    ("color", "#dff8ff"),
                    ("font-family", "JetBrains Mono, monospace"),
                    ("font-size", "11px"),
                    ("font-weight", "700"),
                    ("border-bottom", "1px solid rgba(57,231,255,.34)"),
                ],
            },
            {
                "selector": "tbody tr:nth-child(even) td",
                "props": [("background-color", "rgba(12,31,56,.48)")],
            },
        ],
        overwrite=False,
    )
    return styler



def _enregistrer_polices_pdf() -> tuple[str, str, str]:
    """Enregistre des polices locales pour un PDF Unicode, avec repli sûr."""
    try:
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
    except ImportError as exc:
        raise RuntimeError(
            "La bibliothèque ReportLab est requise pour l'export PDF. "
            "Installez-la avec : pip install reportlab"
        ) from exc

    familles = [
        (
            Path("C:/Windows/Fonts/segoeui.ttf"),
            Path("C:/Windows/Fonts/segoeuib.ttf"),
            Path("C:/Windows/Fonts/consola.ttf"),
        ),
        (
            Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
            Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
            Path("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"),
        ),
        (
            Path("/Library/Fonts/Arial Unicode.ttf"),
            Path("/Library/Fonts/Arial Bold.ttf"),
            Path("/Library/Fonts/Courier New.ttf"),
        ),
    ]

    for police_texte, police_grasse, police_mono in familles:
        if police_texte.exists() and police_grasse.exists():
            noms_enregistres = set(pdfmetrics.getRegisteredFontNames())
            if "SOCText" not in noms_enregistres:
                pdfmetrics.registerFont(TTFont("SOCText", str(police_texte)))
            if "SOCTextBold" not in noms_enregistres:
                pdfmetrics.registerFont(TTFont("SOCTextBold", str(police_grasse)))
            if police_mono.exists() and "SOCMono" not in noms_enregistres:
                pdfmetrics.registerFont(TTFont("SOCMono", str(police_mono)))
            return (
                "SOCText",
                "SOCTextBold",
                "SOCMono" if police_mono.exists() else "Courier",
            )

    return "Helvetica", "Helvetica-Bold", "Courier"


def _valeur_pdf(value: object) -> str:
    """Nettoie une valeur tabulaire avant son insertion dans un Paragraph ReportLab."""
    if value is None:
        return "-"
    try:
        if pd.isna(value):
            return "-"
    except (TypeError, ValueError):
        pass

    texte = str(value).strip()
    if not texte:
        return "-"
    return escape(texte).replace("\n", "<br/>")


def generer_pdf_registre_filtre(
    dataframe: pd.DataFrame,
    filtres: dict[str, str],
) -> bytes:
    """Génère un registre PDF clair, lisible et adapté à l'impression."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.pdfgen import canvas as pdf_canvas
        from reportlab.platypus import (
            LongTable,
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:
        raise RuntimeError(
            "La bibliothèque ReportLab est requise pour l'export PDF. "
            "Installez-la avec : pip install reportlab"
        ) from exc

    font_texte, font_gras, font_mono = _enregistrer_polices_pdf()

    # Palette volontairement claire : le thème sombre du site ne convient pas
    # à un document imprimé ou affiché dans un lecteur PDF.
    couleur_bleu = colors.HexColor("#123B5D")
    couleur_bleu_2 = colors.HexColor("#1E5A7A")
    couleur_cyan = colors.HexColor("#00A6A6")
    couleur_texte = colors.HexColor("#17212B")
    couleur_secondaire = colors.HexColor("#536474")
    couleur_bordure = colors.HexColor("#CAD6DF")
    couleur_ligne = colors.HexColor("#F3F7FA")
    couleur_surface = colors.HexColor("#EAF4F7")
    couleur_succes = colors.HexColor("#147D64")
    couleur_succes_fond = colors.HexColor("#E6F5EF")
    couleur_attention = colors.HexColor("#9A6500")
    couleur_attention_fond = colors.HexColor("#FFF3D5")
    couleur_danger = colors.HexColor("#B02A37")
    couleur_danger_fond = colors.HexColor("#FCE8EA")
    couleur_elevee = colors.HexColor("#B54A16")
    couleur_elevee_fond = colors.HexColor("#FDEDE4")

    page_size = landscape(A4)
    largeur_page, hauteur_page = page_size
    marge = 11 * mm
    largeur_utile = largeur_page - (2 * marge)

    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=page_size,
        rightMargin=marge,
        leftMargin=marge,
        topMargin=18 * mm,
        bottomMargin=14 * mm,
        title=f"Registre filtré des incidents - {APP_NAME}",
        author=APP_NAME,
        subject="Export opérationnel des incidents de cybersécurité",
    )

    styles_base = getSampleStyleSheet()
    style_marque = ParagraphStyle(
        "SOCMarque",
        parent=styles_base["Normal"],
        fontName=font_gras,
        fontSize=8,
        leading=10,
        textColor=couleur_bleu_2,
        spaceAfter=3,
    )
    style_titre = ParagraphStyle(
        "SOCTitre",
        parent=styles_base["Title"],
        fontName=font_gras,
        fontSize=19,
        leading=22,
        textColor=couleur_bleu,
        spaceAfter=4,
    )
    style_sous_titre = ParagraphStyle(
        "SOCSousTitre",
        parent=styles_base["Normal"],
        fontName=font_texte,
        fontSize=8.7,
        leading=12,
        textColor=couleur_secondaire,
        spaceAfter=8,
    )
    style_section = ParagraphStyle(
        "SOCSection",
        parent=styles_base["Heading2"],
        fontName=font_gras,
        fontSize=11.5,
        leading=14,
        textColor=couleur_bleu,
        spaceBefore=7,
        spaceAfter=5,
    )
    style_filtre_label = ParagraphStyle(
        "SOCFiltreLabel",
        parent=styles_base["Normal"],
        fontName=font_gras,
        fontSize=6.7,
        leading=8.5,
        textColor=couleur_bleu_2,
    )
    style_filtre_valeur = ParagraphStyle(
        "SOCFiltreValeur",
        parent=styles_base["Normal"],
        fontName=font_texte,
        fontSize=8.4,
        leading=10.5,
        textColor=couleur_texte,
    )
    style_kpi_label = ParagraphStyle(
        "SOCKPILabel",
        parent=styles_base["Normal"],
        fontName=font_gras,
        fontSize=6.5,
        leading=8,
        textColor=couleur_secondaire,
        alignment=TA_CENTER,
    )
    style_kpi_valeur = ParagraphStyle(
        "SOCKPIValue",
        parent=styles_base["Normal"],
        fontName=font_gras,
        fontSize=14,
        leading=17,
        textColor=couleur_bleu,
        alignment=TA_CENTER,
    )
    style_resume = ParagraphStyle(
        "SOCResume",
        parent=styles_base["Normal"],
        fontName=font_texte,
        fontSize=8.7,
        leading=12.5,
        textColor=couleur_texte,
        alignment=TA_LEFT,
    )
    style_entete_table = ParagraphStyle(
        "SOCEnteteTable",
        parent=styles_base["Normal"],
        fontName=font_gras,
        fontSize=7,
        leading=8.5,
        textColor=colors.white,
        alignment=TA_CENTER,
    )
    style_cellule = ParagraphStyle(
        "SOCCellule",
        parent=styles_base["Normal"],
        fontName=font_texte,
        fontSize=7.1,
        leading=9,
        textColor=couleur_texte,
        alignment=TA_LEFT,
        wordWrap="CJK",
    )
    style_cellule_mono = ParagraphStyle(
        "SOCCelluleMono",
        parent=style_cellule,
        fontName=font_mono,
        fontSize=6.6,
        leading=8.5,
    )
    style_numero = ParagraphStyle(
        "SOCNumero",
        parent=style_cellule,
        fontName=font_gras,
        textColor=couleur_bleu_2,
        alignment=TA_CENTER,
    )

    horodatage_generation = datetime.now().strftime("%d/%m/%Y à %H:%M:%S")

    def dessiner_entete_pied(canvas, numero_page: int) -> None:
        canvas.saveState()
        canvas.setFillColor(couleur_bleu)
        canvas.rect(0, hauteur_page - 4 * mm, largeur_page, 4 * mm, stroke=0, fill=1)
        canvas.setStrokeColor(couleur_bordure)
        canvas.setLineWidth(0.55)
        canvas.line(marge, hauteur_page - 11 * mm, largeur_page - marge, hauteur_page - 11 * mm)
        canvas.setFont(font_gras, 7.2)
        canvas.setFillColor(couleur_bleu)
        canvas.drawString(marge, hauteur_page - 9 * mm, "SUPERVISION DES CYBERATTAQUES")
        canvas.setFont(font_texte, 6.7)
        canvas.setFillColor(couleur_secondaire)
        canvas.drawRightString(largeur_page - marge, hauteur_page - 9 * mm, "REGISTRE DES INCIDENTS")

        canvas.setStrokeColor(couleur_bordure)
        canvas.line(marge, 9.5 * mm, largeur_page - marge, 9.5 * mm)
        canvas.setFont(font_texte, 6.5)
        canvas.setFillColor(couleur_secondaire)
        canvas.drawString(marge, 6.2 * mm, f"Généré le {horodatage_generation}")
        canvas.drawRightString(
            largeur_page - marge,
            6.2 * mm,
            f"Page {numero_page}",
        )
        canvas.restoreState()

    class CanvasRapport(pdf_canvas.Canvas):
        """Dessine l'en-tête après le contenu pour éviter tout recouvrement."""

        def showPage(self) -> None:  # noqa: N802
            dessiner_entete_pied(self, self._pageNumber)
            super().showPage()

    dataframe_source = dataframe.copy()
    dataframe_pdf = dataframe_professionnel(dataframe_source)

    total = len(dataframe_source)
    total_traites = 0
    total_a_traiter = 0
    if "statut" in dataframe_source.columns:
        statuts_bruts = dataframe_source["statut"].fillna("").astype(str)
        total_traites = int((statuts_bruts == "Traitee").sum())
        total_a_traiter = int((statuts_bruts != "Traitee").sum())

    def valeur_dominante(colonne: str, defaut: str = "Non disponible") -> str:
        if colonne not in dataframe_source.columns or dataframe_source.empty:
            return defaut
        valeurs = dataframe_source[colonne].fillna("").astype(str)
        valeurs = valeurs[valeurs.str.strip() != ""]
        if valeurs.empty:
            return defaut
        return str(libelle_professionnel(valeurs.value_counts().idxmax()))

    source_principale = valeur_dominante("source")
    gravite_principale = valeur_dominante("gravite")
    classe_principale = valeur_dominante("classe")

    story: list[object] = [
        Spacer(1, 1 * mm),
        Paragraph("RAPPORT OPÉRATIONNEL", style_marque),
        Paragraph("Registre des incidents de cybersécurité", style_titre),
        Paragraph(
            "Vue consolidée des événements correspondant au périmètre actif. "
            f"Export généré le {horodatage_generation}.",
            style_sous_titre,
        ),
    ]

    # Périmètre actif sous forme de trois cartes.
    filtres_normalises = {
        "Moteur de détection": filtres.get("source", "Tous les moteurs"),
        "Niveau de sévérité": filtres.get("gravite", "Tous les niveaux"),
        "Statut de traitement": filtres.get("statut", "Tous les statuts"),
    }
    cellules_filtres = []
    for libelle, valeur in filtres_normalises.items():
        cellules_filtres.append(
            [
                Paragraph(escape(libelle.upper()), style_filtre_label),
                Paragraph(_valeur_pdf(valeur), style_filtre_valeur),
            ]
        )
    table_filtres = Table(
        [[Table([[item[0]], [item[1]]], colWidths=[largeur_utile / 3 - 10 * mm]) for item in cellules_filtres]],
        colWidths=[largeur_utile / 3] * 3,
        hAlign="LEFT",
    )
    table_filtres.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), couleur_surface),
                ("BOX", (0, 0), (-1, -1), 0.6, couleur_bordure),
                ("INNERGRID", (0, 0), (-1, -1), 0.35, couleur_bordure),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    story.extend([table_filtres, Spacer(1, 5 * mm)])

    # KPI principaux du périmètre filtré.
    kpis = [
        ("ÉVÉNEMENTS FILTRÉS", formater_nombre(total), couleur_bleu_2),
        ("INCIDENTS TRAITÉS", formater_nombre(total_traites), couleur_succes),
        ("INCIDENTS À TRAITER", formater_nombre(total_a_traiter), couleur_danger),
        ("SÉVÉRITÉ DOMINANTE", gravite_principale, couleur_attention),
    ]
    cellules_kpi = []
    for label, valeur, couleur_accent in kpis:
        cellule = Table(
            [
                [Paragraph(escape(label), style_kpi_label)],
                [Paragraph(_valeur_pdf(valeur), style_kpi_valeur)],
            ],
            colWidths=[largeur_utile / 4 - 6 * mm],
        )
        cellule.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                    ("BOX", (0, 0), (-1, -1), 0.85, couleur_accent),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        cellules_kpi.append(cellule)

    table_kpi = Table([cellules_kpi], colWidths=[largeur_utile / 4] * 4)
    table_kpi.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 3),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    story.extend([table_kpi, Spacer(1, 4 * mm)])

    story.append(Paragraph("Synthèse opérationnelle", style_section))
    resume = (
        f"Le périmètre contient <b>{formater_nombre(total)} événement(s)</b>. "
        f"Le moteur le plus représenté est <b>{escape(source_principale)}</b>, "
        f"la sévérité dominante est <b>{escape(gravite_principale)}</b> et la menace "
        f"la plus fréquente est <b>{escape(classe_principale)}</b>."
    )
    story.extend([Paragraph(resume, style_resume), Spacer(1, 3 * mm)])

    story.append(Paragraph("Détail des événements", style_section))

    if dataframe_pdf.empty:
        message_vide = Table(
            [[Paragraph("Aucun événement ne correspond aux filtres sélectionnés.", style_resume)]],
            colWidths=[largeur_utile],
        )
        message_vide.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), couleur_surface),
                    ("BOX", (0, 0), (-1, -1), 0.7, couleur_bordure),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                    ("TOPPADDING", (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ]
            )
        )
        story.append(message_vide)
    else:
        # Le tableau principal reste volontairement limité aux informations
        # opérationnelles. Les textes longs sont placés dans une annexe afin
        # de conserver une taille de police réellement lisible.
        colonnes_principales = [
            "Horodatage",
            "Moteur de détection",
            "Type de menace",
            "Niveau de sévérité",
            "Adresse IP source",
            "Adresse IP de destination",
            "Protocole réseau",
            "Statut de traitement",
            "État de notification",
        ]
        colonnes_pdf = [col for col in colonnes_principales if col in dataframe_pdf.columns]
        if not colonnes_pdf:
            colonnes_pdf = list(dataframe_pdf.columns[:8])

        poids = {
            "Horodatage": 1.35,
            "Moteur de détection": 0.95,
            "Type de menace": 1.35,
            "Niveau de sévérité": 0.80,
            "Adresse IP source": 1.05,
            "Adresse IP de destination": 1.05,
            "Protocole réseau": 0.65,
            "Statut de traitement": 0.88,
            "État de notification": 0.90,
        }
        poids_colonnes = [0.38] + [poids.get(col, 1.0) for col in colonnes_pdf]
        somme_poids = sum(poids_colonnes)
        largeurs = [largeur_utile * poids_col / somme_poids for poids_col in poids_colonnes]

        donnees_table = [
            [Paragraph("N°", style_entete_table)]
            + [Paragraph(escape(str(col)), style_entete_table) for col in colonnes_pdf]
        ]
        colonnes_mono = {
            "Horodatage",
            "Adresse IP source",
            "Adresse IP de destination",
            "Protocole réseau",
        }
        for numero, (_, ligne) in enumerate(dataframe_pdf[colonnes_pdf].iterrows(), start=1):
            cellules = [Paragraph(str(numero), style_numero)]
            for colonne in colonnes_pdf:
                style_utilise = style_cellule_mono if colonne in colonnes_mono else style_cellule
                cellules.append(Paragraph(_valeur_pdf(ligne[colonne]), style_utilise))
            donnees_table.append(cellules)

        commandes_style = [
            ("BACKGROUND", (0, 0), (-1, 0), couleur_bleu),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("BOX", (0, 0), (-1, -1), 0.65, couleur_bordure),
            ("INNERGRID", (0, 0), (-1, -1), 0.3, couleur_bordure),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, couleur_ligne]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4.2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4.2),
        ]

        # Accent sémantique sur la sévérité, le statut et la notification.
        if "Niveau de sévérité" in colonnes_pdf:
            index_gravite = colonnes_pdf.index("Niveau de sévérité") + 1
            couleurs_gravite = {
                "Critique": (couleur_danger, couleur_danger_fond),
                "Élevée": (couleur_elevee, couleur_elevee_fond),
                "Moyenne": (couleur_attention, couleur_attention_fond),
                "Faible": (couleur_succes, couleur_succes_fond),
            }
            for numero_ligne, valeur in enumerate(
                dataframe_pdf["Niveau de sévérité"].astype(str),
                start=1,
            ):
                couleur, fond = couleurs_gravite.get(
                    valeur,
                    (couleur_texte, colors.white),
                )
                commandes_style.extend(
                    [
                        ("TEXTCOLOR", (index_gravite, numero_ligne), (index_gravite, numero_ligne), couleur),
                        ("BACKGROUND", (index_gravite, numero_ligne), (index_gravite, numero_ligne), fond),
                        ("FONTNAME", (index_gravite, numero_ligne), (index_gravite, numero_ligne), font_gras),
                    ]
                )

        if "Statut de traitement" in colonnes_pdf:
            index_statut = colonnes_pdf.index("Statut de traitement") + 1
            for numero_ligne, valeur in enumerate(
                dataframe_pdf["Statut de traitement"].astype(str),
                start=1,
            ):
                couleur = couleur_succes if valeur == "Traité" else couleur_attention
                fond = couleur_succes_fond if valeur == "Traité" else couleur_attention_fond
                commandes_style.extend(
                    [
                        ("TEXTCOLOR", (index_statut, numero_ligne), (index_statut, numero_ligne), couleur),
                        ("BACKGROUND", (index_statut, numero_ligne), (index_statut, numero_ligne), fond),
                    ]
                )

        if "État de notification" in colonnes_pdf:
            index_notification = colonnes_pdf.index("État de notification") + 1
            for numero_ligne, valeur in enumerate(
                dataframe_pdf["État de notification"].astype(str),
                start=1,
            ):
                couleur = couleur_succes if valeur == "Transmis" else couleur_danger
                fond = couleur_succes_fond if valeur == "Transmis" else couleur_danger_fond
                commandes_style.extend(
                    [
                        ("TEXTCOLOR", (index_notification, numero_ligne), (index_notification, numero_ligne), couleur),
                        ("BACKGROUND", (index_notification, numero_ligne), (index_notification, numero_ligne), fond),
                    ]
                )

        table_evenements = LongTable(
            donnees_table,
            colWidths=largeurs,
            repeatRows=1,
            hAlign="LEFT",
            splitByRow=1,
        )
        table_evenements.setStyle(TableStyle(commandes_style))
        story.append(table_evenements)

        colonnes_details = [
            colonne
            for colonne in [
                "Élément analysé",
                "Signature IDS",
                "Mesure de réponse recommandée",
                "Détails techniques",
            ]
            if colonne in dataframe_pdf.columns
        ]
        if colonnes_details:
            valeurs_details = dataframe_pdf[colonnes_details].fillna("").astype(str)
            if valeurs_details.apply(lambda serie: serie.str.strip().ne("")).any().any():
                story.extend(
                    [
                        PageBreak(),
                        Paragraph("Annexe - Détails complémentaires", style_section),
                        Paragraph(
                            "Cette annexe reprend les champs textuels longs séparément "
                            "afin de préserver la lisibilité du registre principal.",
                            style_sous_titre,
                        ),
                    ]
                )

                poids_details = {
                    "Élément analysé": 1.2,
                    "Signature IDS": 1.6,
                    "Mesure de réponse recommandée": 2.0,
                    "Détails techniques": 2.0,
                }
                poids_annexe = [0.38] + [poids_details.get(col, 1.0) for col in colonnes_details]
                somme_annexe = sum(poids_annexe)
                largeurs_annexe = [
                    largeur_utile * poids_col / somme_annexe
                    for poids_col in poids_annexe
                ]
                entete_annexe = [Paragraph("N°", style_entete_table)] + [
                    Paragraph(escape(str(colonne)), style_entete_table)
                    for colonne in colonnes_details
                ]
                # Une ligne transparente répétée réserve la zone de l'en-tête
                # du document sur chaque page de continuation de l'annexe.
                donnees_annexe = [
                    [Spacer(1, 7 * mm) for _ in entete_annexe],
                    entete_annexe,
                ]
                for numero, (_, ligne) in enumerate(
                    dataframe_pdf[colonnes_details].iterrows(),
                    start=1,
                ):
                    donnees_annexe.append(
                        [Paragraph(str(numero), style_numero)]
                        + [
                            Paragraph(_valeur_pdf(ligne[colonne]), style_cellule)
                            for colonne in colonnes_details
                        ]
                    )

                table_annexe = LongTable(
                    donnees_annexe,
                    colWidths=largeurs_annexe,
                    repeatRows=2,
                    hAlign="LEFT",
                    splitByRow=1,
                )
                table_annexe.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 1), (-1, 1), couleur_bleu_2),
                            ("TEXTCOLOR", (0, 1), (-1, 1), colors.white),
                            ("BOX", (0, 1), (-1, -1), 0.65, couleur_bordure),
                            ("INNERGRID", (0, 1), (-1, -1), 0.3, couleur_bordure),
                            ("ROWBACKGROUNDS", (0, 2), (-1, -1), [colors.white, couleur_ligne]),
                            ("VALIGN", (0, 1), (-1, -1), "TOP"),
                            ("LEFTPADDING", (0, 1), (-1, -1), 4.5),
                            ("RIGHTPADDING", (0, 1), (-1, -1), 4.5),
                            ("TOPPADDING", (0, 0), (-1, 0), 0),
                            ("BOTTOMPADDING", (0, 0), (-1, 0), 0),
                            ("TOPPADDING", (0, 1), (-1, -1), 3.2),
                            ("BOTTOMPADDING", (0, 1), (-1, -1), 3.2),
                        ]
                    )
                )
                story.append(table_annexe)

    document.build(story, canvasmaker=CanvasRapport)
    buffer.seek(0)
    return buffer.getvalue()


@st.cache_data(show_spinner=False, max_entries=8)
def preparer_pdf_registre_filtre(
    dataframe: pd.DataFrame,
    filtres: dict[str, str],
) -> bytes:
    """Prépare et valide le PDF avant de l'exposer au navigateur."""
    contenu_pdf = generer_pdf_registre_filtre(dataframe, filtres)
    if not isinstance(contenu_pdf, bytes) or not contenu_pdf.startswith(b"%PDF-"):
        raise RuntimeError("Le document produit n'est pas un fichier PDF valide.")
    return contenu_pdf


def afficher_erreur_api(response: requests.Response) -> None:
    st.error("Le service d'analyse n'a pas pu traiter la demande.")
    with st.expander("Consulter les détails techniques"):
        st.code(response.text or f"Code HTTP : {response.status_code}")


def dataframe_from_dict_counter(data: dict[str, int], key_name: str) -> pd.DataFrame:
    lignes = [(libelle_professionnel(key), value) for key, value in data.items()]
    return pd.DataFrame(lignes, columns=[key_name, "Volume d'événements"])


def render_donut_chart(
    dataframe: pd.DataFrame,
    label_column: str,
    value_column: str,
    title: str,
    subtitle: str,
    colors: dict[str, str] | None = None,
) -> None:
    """Affiche un diagramme en anneau adapté au tableau de bord SOC."""
    if dataframe.empty or dataframe[value_column].sum() <= 0:
        st.info("Aucune donnée disponible pour cette répartition.")
        return

    chart_data = dataframe.copy()
    chart_data[value_column] = pd.to_numeric(
        chart_data[value_column], errors="coerce"
    ).fillna(0)
    chart_data = chart_data[chart_data[value_column] > 0].sort_values(
        value_column, ascending=False
    )

    labels = chart_data[label_column].astype(str).tolist()
    values = chart_data[value_column].astype(float).tolist()
    total = int(sum(values))

    default_palette = [
        "#24D8FF",
        "#7C5CFF",
        "#30F2A2",
        "#FFC857",
        "#FF4F91",
        "#B072FF",
        "#7E97B7",
    ]
    marker_colors = [
        (colors or {}).get(label, default_palette[index % len(default_palette)])
        for index, label in enumerate(labels)
    ]

    figure = go.Figure(
        data=[
            go.Pie(
                labels=labels,
                values=values,
                hole=0.66,
                sort=False,
                direction="clockwise",
                textinfo="percent",
                textposition="inside",
                insidetextorientation="horizontal",
                marker={
                    "colors": marker_colors,
                    "line": {"color": "#081225", "width": 3},
                },
                hovertemplate=(
                    "<b>%{label}</b><br>"
                    "Événements : %{value:,.0f}<br>"
                    "Part : %{percent}<extra></extra>"
                ),
            )
        ]
    )

    figure.update_layout(
        title={
            "text": (
                f"<b>{escape(title)}</b>"
                f"<br><span style='font-size:12px;color:#A9B7CE'>"
                f"{escape(subtitle)}</span>"
            ),
            "x": 0.02,
            "xanchor": "left",
            "y": 0.97,
            "yanchor": "top",
            "font": {"family": "Space Grotesk, sans-serif", "size": 16, "color": "#F4F8FF"},
        },
        annotations=[
            {
                "text": (
                    f"<span style='font-size:11px;color:#A9B7CE'>Total</span>"
                    f"<br><b style='font-size:23px;color:#F4F8FF'>"
                    f"{formater_nombre(total)}</b>"
                ),
                "x": 0.5,
                "y": 0.5,
                "showarrow": False,
                "align": "center",
            }
        ],
        legend={
            "orientation": "h",
            "yanchor": "top",
            "y": -0.10,
            "xanchor": "center",
            "x": 0.5,
            "font": {"family": "IBM Plex Sans, sans-serif", "size": 11, "color": "#C7D5E8"},
        },
        margin={"l": 18, "r": 18, "t": 86, "b": 78},
        height=402,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"family": "IBM Plex Sans, sans-serif", "color": "#F4F8FF"},
        hoverlabel={
            "bgcolor": "#071225",
            "font": {"color": "#F4F8FF", "size": 12},
            "bordercolor": "#39E7FF",
        },
        uniformtext_minsize=10,
        uniformtext_mode="hide",
    )

    st.plotly_chart(
        figure,
        use_container_width=True,
        config={"displayModeBar": False, "responsive": True},
        theme=None,
    )


RISK_LEVEL_SCORES = {
    "MAITRISE": 15,
    "FAIBLE": 25,
    "MODERE": 50,
    "MOYEN": 50,
    "ELEVE": 75,
    "ELEVEE": 75,
    "CRITIQUE": 95,
}

BENIGN_LABELS = {
    "BENIGN",
    "BENIN",
    "NORMAL",
    "NORMAL TRAFFIC",
    "TRAFFIC NORMAL",
    "TRAFIC NORMAL",
}

PERIOD_OPTIONS = {
    "Toutes les données": None,
    "Dernières 24 heures": pd.Timedelta(hours=24),
    "7 derniers jours": pd.Timedelta(days=7),
    "30 derniers jours": pd.Timedelta(days=30),
}


def _normaliser_cle(value: object) -> str:
    return (
        str(value or "")
        .strip()
        .upper()
        .replace("É", "E")
        .replace("È", "E")
        .replace("Ê", "E")
        .replace("À", "A")
        .replace("Â", "A")
        .replace("Î", "I")
        .replace("Ô", "O")
        .replace("Ù", "U")
        .replace("Û", "U")
    )


def _premiere_valeur(mapping: dict, keys: list[str], default: object = None) -> object:
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return mapping[key]
    return default


def preparer_historique(history: list[dict] | None) -> pd.DataFrame:
    dataframe = pd.DataFrame(history or [])
    if dataframe.empty:
        return dataframe

    if "date" not in dataframe.columns:
        dataframe["date"] = pd.NaT

    dataframe["_date"] = pd.to_datetime(
        dataframe["date"],
        errors="coerce",
        utc=True,
    ).dt.tz_convert(None)

    if "nombre" in dataframe.columns:
        dataframe["_occurrences"] = pd.to_numeric(
            dataframe["nombre"], errors="coerce"
        ).fillna(1)
    else:
        dataframe["_occurrences"] = 1

    dataframe["_occurrences"] = dataframe["_occurrences"].clip(lower=0)

    if "classe" not in dataframe.columns:
        dataframe["classe"] = "Non définie"

    dataframe["_est_benin"] = dataframe["classe"].map(
        lambda value: _normaliser_cle(value) in BENIGN_LABELS
        or "BENIGN" in _normaliser_cle(value)
    )

    return dataframe


def filtrer_historique_par_periode(
    dataframe: pd.DataFrame,
    periode: str,
) -> pd.DataFrame:
    if dataframe.empty or periode not in PERIOD_OPTIONS:
        return dataframe.copy()

    delta = PERIOD_OPTIONS[periode]
    if delta is None or dataframe["_date"].dropna().empty:
        return dataframe.copy()

    date_reference = max(pd.Timestamp.now(), dataframe["_date"].max())
    date_limite = date_reference - delta
    return dataframe[dataframe["_date"] >= date_limite].copy()


def extraire_repartition_attaques(
    stats: dict,
    historique: pd.DataFrame,
) -> pd.DataFrame:
    repartition = (
        stats.get("par_classe")
        or stats.get("par_attaque")
        or stats.get("distribution_classes")
        or stats.get("types_attaques")
        or {}
    )

    if isinstance(repartition, dict) and repartition:
        dataframe = pd.DataFrame(
            [
                {
                    "Type de menace": str(libelle_professionnel(label)),
                    "Occurrences": pd.to_numeric(volume, errors="coerce"),
                }
                for label, volume in repartition.items()
            ]
        )
    elif not historique.empty:
        dataframe = (
            historique.loc[~historique["_est_benin"]]
            .groupby("classe", dropna=False)["_occurrences"]
            .sum()
            .reset_index()
            .rename(
                columns={
                    "classe": "Type de menace",
                    "_occurrences": "Occurrences",
                }
            )
        )
    else:
        return pd.DataFrame(columns=["Type de menace", "Occurrences"])

    if dataframe.empty:
        return dataframe

    dataframe["Occurrences"] = pd.to_numeric(
        dataframe["Occurrences"], errors="coerce"
    ).fillna(0)
    dataframe["Type de menace"] = dataframe["Type de menace"].astype(str)
    dataframe = dataframe[
        ~dataframe["Type de menace"].map(
            lambda value: _normaliser_cle(value) in BENIGN_LABELS
            or "BENIGN" in _normaliser_cle(value)
        )
    ]
    dataframe = dataframe[dataframe["Occurrences"] > 0]
    dataframe = dataframe.sort_values("Occurrences", ascending=False)

    if len(dataframe) > 7:
        principales = dataframe.head(6).copy()
        autres = dataframe.iloc[6:]["Occurrences"].sum()
        dataframe = pd.concat(
            [
                principales,
                pd.DataFrame(
                    [{"Type de menace": "Autres attaques", "Occurrences": autres}]
                ),
            ],
            ignore_index=True,
        )

    return dataframe


def construire_serie_temporelle(
    stats: dict,
    historique: pd.DataFrame,
) -> pd.DataFrame:
    serie_source = (
        stats.get("evolution_trafic")
        or stats.get("trafic_temporel")
        or stats.get("serie_temporelle")
        or stats.get("timeline")
        or []
    )

    lignes: list[dict] = []
    if isinstance(serie_source, list):
        for item in serie_source:
            if not isinstance(item, dict):
                continue

            date_value = _premiere_valeur(
                item,
                ["horodatage", "date", "periode", "timestamp", "time"],
            )
            date = pd.to_datetime(date_value, errors="coerce", utc=True)
            if pd.isna(date):
                continue

            benin = _premiere_valeur(
                item,
                ["benin", "benign", "trafic_benin", "flux_benins", "normal"],
                0,
            )
            malveillant = _premiere_valeur(
                item,
                [
                    "malveillant",
                    "malicious",
                    "trafic_malveillant",
                    "flux_malveillants",
                    "attaques",
                ],
                0,
            )

            benin_num = pd.to_numeric(benin, errors="coerce")
            malveillant_num = pd.to_numeric(malveillant, errors="coerce")
            benin_num = 0 if pd.isna(benin_num) else float(benin_num)
            malveillant_num = (
                0 if pd.isna(malveillant_num) else float(malveillant_num)
            )

            lignes.append(
                {
                    "Horodatage": date.tz_convert(None),
                    "Trafic bénin": benin_num,
                    "Trafic malveillant": malveillant_num,
                }
            )

    if lignes:
        dataframe = pd.DataFrame(lignes)
        return (
            dataframe.groupby("Horodatage", as_index=False)[
                ["Trafic bénin", "Trafic malveillant"]
            ]
            .sum()
            .sort_values("Horodatage")
        )

    if historique.empty or historique["_date"].dropna().empty:
        return pd.DataFrame(
            columns=["Horodatage", "Trafic bénin", "Trafic malveillant"]
        )

    dates = historique["_date"].dropna()
    amplitude = dates.max() - dates.min()
    if amplitude <= pd.Timedelta(days=2):
        frequence = "h"
    elif amplitude <= pd.Timedelta(days=90):
        frequence = "D"
    else:
        frequence = "W"

    dataframe = historique.dropna(subset=["_date"]).copy()
    dataframe["Horodatage"] = dataframe["_date"].dt.floor(frequence)
    dataframe["Trafic bénin"] = dataframe["_occurrences"].where(
        dataframe["_est_benin"], 0
    )
    dataframe["Trafic malveillant"] = dataframe["_occurrences"].where(
        ~dataframe["_est_benin"], 0
    )

    return (
        dataframe.groupby("Horodatage", as_index=False)[
            ["Trafic bénin", "Trafic malveillant"]
        ]
        .sum()
        .sort_values("Horodatage")
    )


def filtrer_serie_par_periode(
    dataframe: pd.DataFrame,
    periode: str,
) -> pd.DataFrame:
    if dataframe.empty or periode not in PERIOD_OPTIONS:
        return dataframe.copy()

    delta = PERIOD_OPTIONS[periode]
    if delta is None:
        return dataframe.copy()

    date_reference = max(pd.Timestamp.now(), dataframe["Horodatage"].max())
    return dataframe[dataframe["Horodatage"] >= date_reference - delta].copy()


def render_risk_gauge(risque: dict) -> None:
    niveau = str(libelle_professionnel(risque.get("niveau", "Non disponible")))
    score_brut = risque.get("score", risque.get("valeur"))
    score = pd.to_numeric(score_brut, errors="coerce")

    if not risque or (pd.isna(score) and _normaliser_cle(niveau) == "NON DISPONIBLE"):
        st.markdown(
            """
            <div class="soc-gauge-heading">
                <div class="soc-gauge-heading__label">Niveau de risque global</div>
                <div class="soc-gauge-heading__value">—</div>
            </div>
            <div class="soc-gauge-empty">
                Le niveau de risque apparaîtra après la synchronisation des données.
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    if pd.isna(score):
        score = RISK_LEVEL_SCORES.get(_normaliser_cle(niveau), 0)
    elif score <= 1:
        score *= 100

    score = float(max(0, min(100, score)))

    if score < 30:
        couleur_risque = "#30F2A2"
    elif score < 60:
        couleur_risque = "#FFC857"
    elif score < 80:
        couleur_risque = "#FF8A5B"
    else:
        couleur_risque = "#FF4F91"

    # Le libellé et le niveau sont volontairement placés hors du graphique.
    # Cela supprime tout chevauchement avec les graduations de la jauge.
    st.markdown(
        f"""
        <div class="soc-gauge-heading">
            <div class="soc-gauge-heading__label">Niveau de risque global</div>
            <div class="soc-gauge-heading__value" style="color:{couleur_risque}">
                {escape(niveau)}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    figure = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            domain={"x": [0.05, 0.95], "y": [0.05, 0.96]},
            number={
                "suffix": "%",
                "valueformat": ".0f",
                "font": {
                    "family": "JetBrains Mono, monospace",
                    "size": 27,
                    "color": "#F4F8FF",
                },
            },
            gauge={
                "shape": "angular",
                "axis": {
                    "range": [0, 100],
                    "tickmode": "array",
                    "tickvals": [0, 25, 50, 75, 100],
                    "ticktext": ["0", "25", "50", "75", "100"],
                    "tickfont": {
                        "family": "JetBrains Mono, monospace",
                        "size": 9,
                        "color": "#9FB0C8",
                    },
                    "tickwidth": 0,
                },
                "bar": {"color": couleur_risque, "thickness": 0.22},
                "bgcolor": "rgba(17,37,67,0.82)",
                "borderwidth": 0,
                "steps": [
                    {"range": [0, 30], "color": "rgba(48,242,162,0.18)"},
                    {"range": [30, 60], "color": "rgba(255,200,87,0.18)"},
                    {"range": [60, 80], "color": "rgba(255,138,91,0.20)"},
                    {"range": [80, 100], "color": "rgba(255,79,145,0.22)"},
                ],
                "threshold": {
                    "line": {"color": couleur_risque, "width": 3},
                    "thickness": 0.75,
                    "value": score,
                },
            },
        )
    )

    figure.update_layout(
        height=184,
        margin={"l": 28, "r": 28, "t": 0, "b": 4},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"family": "IBM Plex Sans, sans-serif", "color": "#F4F8FF"},
    )
    st.plotly_chart(
        figure,
        use_container_width=True,
        theme=None,
        config={"displayModeBar": False, "responsive": True},
    )


def render_time_series_chart(dataframe: pd.DataFrame) -> None:
    if dataframe.empty:
        st.info(
            "La courbe temporelle sera disponible après l'enregistrement de plusieurs "
            "analyses horodatées."
        )
        return

    figure = go.Figure()
    benin_disponible = dataframe["Trafic bénin"].sum() > 0

    if benin_disponible:
        figure.add_trace(
            go.Scatter(
                x=dataframe["Horodatage"],
                y=dataframe["Trafic bénin"],
                mode="lines+markers",
                name="Trafic bénin",
                line={"color": "#30F2A2", "width": 3},
                marker={"size": 7, "line": {"color": "#071225", "width": 1}},
                hovertemplate=(
                    "<b>%{x|%d/%m/%Y %H:%M}</b><br>"
                    "Trafic bénin : %{y:,.0f}<extra></extra>"
                ),
            )
        )

    figure.add_trace(
        go.Scatter(
            x=dataframe["Horodatage"],
            y=dataframe["Trafic malveillant"],
            mode="lines+markers",
            name="Trafic malveillant",
            line={"color": "#FF4F91", "width": 3},
            marker={"size": 7, "line": {"color": "#071225", "width": 1}},
            hovertemplate=(
                "<b>%{x|%d/%m/%Y %H:%M}</b><br>"
                "Trafic malveillant : %{y:,.0f}<extra></extra>"
            ),
        )
    )

    valeurs = dataframe["Trafic malveillant"]
    if len(valeurs) >= 3 and valeurs.max() > 0:
        q1 = valeurs.quantile(0.25)
        q3 = valeurs.quantile(0.75)
        seuil = q3 + 1.5 * (q3 - q1)
        pics = dataframe[valeurs >= seuil]
        if pics.empty:
            pics = dataframe.nlargest(1, "Trafic malveillant")

        figure.add_trace(
            go.Scatter(
                x=pics["Horodatage"],
                y=pics["Trafic malveillant"],
                mode="markers",
                name="Pics suspects",
                marker={
                    "size": 14,
                    "symbol": "diamond",
                    "color": "#FFC857",
                    "line": {"color": "#071225", "width": 2},
                },
                hovertemplate=(
                    "<b>Pic suspect</b><br>%{x|%d/%m/%Y %H:%M}<br>"
                    "Volume : %{y:,.0f}<extra></extra>"
                ),
            )
        )

    # Le nom de la mesure est placé horizontalement au-dessus de la zone de tracé.
    # On évite ainsi le titre vertical qui se superposait aux graduations Y.
    figure.update_layout(
        height=430,
        margin={"l": 72, "r": 30, "t": 82, "b": 72},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(4,13,29,0.18)",
        font={"family": "IBM Plex Sans, sans-serif", "color": "#DCE8F7"},
        hovermode="x unified",
        hoverlabel={
            "bgcolor": "#071225",
            "bordercolor": "#39E7FF",
            "font": {"color": "#F4F8FF", "size": 12},
        },
        legend={
            "orientation": "h",
            "yanchor": "bottom",
            "y": 1.12,
            "xanchor": "right",
            "x": 1,
            "font": {"size": 11, "color": "#C7D5E8"},
            "bgcolor": "rgba(7,18,37,0.42)",
            "bordercolor": "rgba(57,231,255,0.14)",
            "borderwidth": 1,
        },
        annotations=[
            {
                "text": "Volume de flux / événements",
                "x": 0,
                "y": 1.13,
                "xref": "paper",
                "yref": "paper",
                "showarrow": False,
                "xanchor": "left",
                "yanchor": "bottom",
                "font": {
                    "family": "JetBrains Mono, monospace",
                    "size": 11,
                    "color": "#A9B7CE",
                },
            }
        ],
        xaxis={
            "title": {
                "text": "Période",
                "standoff": 18,
                "font": {"size": 12, "color": "#A9B7CE"},
            },
            "showgrid": False,
            "linecolor": "rgba(126,151,183,0.34)",
            "tickfont": {"size": 10, "color": "#A9B7CE"},
            "automargin": True,
            "nticks": 6,
            "tickangle": 0,
        },
        yaxis={
            "title": None,
            "gridcolor": "rgba(126,151,183,0.16)",
            "zerolinecolor": "rgba(126,151,183,0.26)",
            "rangemode": "tozero",
            "tickformat": "~s",
            "tickfont": {
                "family": "JetBrains Mono, monospace",
                "size": 10,
                "color": "#A9B7CE",
            },
            "automargin": True,
            "nticks": 7,
        },
    )

    st.plotly_chart(
        figure,
        use_container_width=True,
        theme=None,
        config={"displayModeBar": False, "responsive": True},
    )

    if not benin_disponible:
        st.caption(
            "Le registre actuel contient uniquement les événements malveillants. "
            "La courbe du trafic bénin apparaîtra lorsque l'API conservera aussi "
            "les volumes bénins par horodatage."
        )


def preparer_evenements_recents(dataframe: pd.DataFrame, limite: int = 8) -> pd.DataFrame:
    if dataframe.empty:
        return pd.DataFrame()

    dataframe = dataframe.sort_values("_date", ascending=False, na_position="last").head(
        limite
    )
    colonnes = [
        "date",
        "ip_source",
        "ip_destination",
        "classe",
        "gravite",
        "statut",
    ]

    resultat = dataframe.copy()
    for colonne in colonnes:
        if colonne not in resultat.columns:
            resultat[colonne] = "Non renseigné"
        resultat[colonne] = resultat[colonne].fillna("Non renseigné").replace(
            "", "Non renseigné"
        )

    return dataframe_professionnel(resultat[colonnes])


def preparer_alertes_recentes(
    notifications: list[dict] | None,
    historique: pd.DataFrame,
    limite: int = 6,
) -> pd.DataFrame:
    dataframe = pd.DataFrame(notifications or [])

    if dataframe.empty and not historique.empty:
        dataframe = historique.copy()

    if dataframe.empty:
        return dataframe

    if "date" not in dataframe.columns:
        dataframe["date"] = pd.NaT

    dataframe["_date"] = pd.to_datetime(
        dataframe["date"], errors="coerce", utc=True
    ).dt.tz_convert(None)
    dataframe = dataframe.sort_values(
        "_date", ascending=False, na_position="last"
    ).head(limite)

    colonnes = ["date", "classe", "gravite", "notification_email", "statut"]
    for colonne in colonnes:
        if colonne not in dataframe.columns:
            dataframe[colonne] = "Non renseigné"
        dataframe[colonne] = dataframe[colonne].fillna("Non renseigné").replace(
            "", "Non renseigné"
        )

    return dataframe_professionnel(dataframe[colonnes])

def afficher_resume_notifications(summary: dict) -> None:
    if not summary:
        return

    render_section_heading(
        "Bilan de diffusion des alertes",
        "État de transmission des notifications par la passerelle de messagerie.",
    )
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Messages transmis", summary.get("gmail_envoyes", 0))
    with col2:
        st.metric("Échecs de transmission", summary.get("echecs", 0))

    echecs = [
        item
        for item in summary.get("details", [])
        if item.get("statut") not in {"Envoyee", "Envoye"}
    ]
    if echecs:
        st.warning(
            "Certaines alertes n'ont pas été transmises. Vérifiez la configuration "
            "de la passerelle de messagerie."
        )
        with st.expander("Détails des transmissions en échec"):
            st.dataframe(
                styliser_tableau_soc(dataframe_professionnel(pd.DataFrame(echecs))),
                use_container_width=True,
                hide_index=True,
            )


def render_system_status_live() -> None:
    try:
        response = get_api("/system-status", timeout=(1.5, 3.5))
        if response.status_code != 200:
            afficher_erreur_api(response)
            return

        status = response.json()
        global_status = str(libelle_professionnel(status.get("statut_global", "Dégradé")))
        api_status = str(libelle_professionnel(status.get("api", "Indisponible")))
        detection_status = str(
            libelle_professionnel(status.get("moteur_detection", "Indisponible"))
        )
        gmail_status = str(libelle_professionnel(status.get("gmail", "Indisponible")))

        last_analysis = status.get("derniere_analyse") or "Aucune analyse enregistrée"
        last_source = str(libelle_professionnel(status.get("derniere_source", "")))
        if last_source:
            analysis_detail = f"Dernière analyse : {last_analysis} · {last_source}"
        else:
            analysis_detail = f"Dernière analyse : {last_analysis}"

        st.markdown(
            f"""
            <div class="soc-live-caption">
                <span class="soc-live-caption__pulse"></span>
                Actualisation automatique toutes les 5 secondes · Dernière synchronisation :
                {escape(str(status.get("horodatage", "Non disponible")))}
            </div>
            """,
            unsafe_allow_html=True,
        )

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            render_status_card(
                "État global de la plateforme",
                global_status,
                analysis_detail,
                "success" if global_status == "Opérationnel" else "warning",
            )
        with col2:
            render_status_card(
                "Service central d'analyse",
                api_status,
                "Connectivité avec l'API FastAPI",
                "success" if api_status == "Opérationnelle" else "danger",
            )
        with col3:
            render_status_card(
                "Moteur de détection",
                detection_status,
                "Disponibilité du classificateur IA",
                "success" if detection_status == "Opérationnel" else "warning",
            )
        with col4:
            render_status_card(
                "Canal d'alerte Gmail",
                gmail_status,
                "Diffusion des notifications de sécurité",
                "success" if gmail_status == "Opérationnelle" else "warning",
            )

    except Exception as exc:  # noqa: BLE001
        st.caption(
            "La synchronisation en quasi temps réel est momentanément indisponible."
        )
        col1, col2, col3, col4 = st.columns(4)
        for colonne, label, detail in [
            (col1, "État global de la plateforme", "Synchronisation interrompue"),
            (col2, "Service central d'analyse", "API momentanément inaccessible"),
            (col3, "Moteur de détection", "État non vérifiable"),
            (col4, "Canal d'alerte Gmail", "État non vérifiable"),
        ]:
            with colonne:
                render_status_card(label, "Indisponible", detail, "danger")
        with st.expander("Consulter les détails techniques"):
            st.code(str(exc))


if hasattr(st, "fragment"):
    render_system_status_live = st.fragment(run_every="5s")(render_system_status_live)


def render_suricata_monitor_live() -> None:
    """Affiche l'état et les dernières alertes du lecteur continu EVE."""
    try:
        response = get_api("/suricata-monitor/status", timeout=(2.5, 6.0))
        if response.status_code != 200:
            afficher_erreur_api(response)
            return

        monitor = response.json()
        operational = bool(
            monitor.get("enabled")
            and monitor.get("thread_alive")
            and monitor.get("file_exists")
            and not monitor.get("last_error")
        )

        if operational:
            st.success(
                "Lecture automatique active : les nouvelles alertes de eve.json "
                "sont ajoutées au registre sans import manuel."
            )
        else:
            diagnostic = monitor.get("last_error") or (
                "Le lecteur automatique n'est pas opérationnel."
            )
            st.error(diagnostic)

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric(
                "Lecteur EVE",
                "Actif" if monitor.get("thread_alive") else "Arrêté",
            )
        with col2:
            st.metric(
                "Fichier surveillé",
                "Détecté" if monitor.get("file_exists") else "Absent",
            )
        with col3:
            st.metric(
                "Nouvelles alertes",
                int(monitor.get("alerts_imported_total", 0)),
            )
        with col4:
            st.metric(
                "Intervalle de lecture",
                f"{monitor.get('poll_interval_seconds', 2):g} s",
            )

        derniere_alerte = monitor.get("last_event_at") or "Aucune depuis le démarrage"
        st.caption(
            f"Dernière alerte détectée : {derniere_alerte} · "
            "Le curseur persistant empêche la réimportation des anciennes lignes."
        )

        alertes_recentes = monitor.get("recent_alerts") or []
        if alertes_recentes:
            df_recentes = pd.DataFrame(alertes_recentes)
            render_section_heading(
                "Dernières alertes Suricata",
                "Mise à jour automatique toutes les cinq secondes.",
            )
            st.dataframe(
                styliser_tableau_soc(dataframe_professionnel(df_recentes)),
                use_container_width=True,
                hide_index=True,
            )
    except Exception as exc:  # noqa: BLE001
        st.error("L'état du lecteur automatique Suricata est indisponible.")
        with st.expander("Consulter les détails techniques"):
            st.code(str(exc))


if hasattr(st, "fragment"):
    render_suricata_monitor_live = st.fragment(run_every="5s")(
        render_suricata_monitor_live
    )


def enregistrer_session_authentifiee(payload: dict) -> None:
    st.session_state["auth_token"] = payload.get("access_token", "")
    st.session_state["auth_user"] = payload.get("user", {})
    st.session_state["auth_expires_at"] = payload.get("expires_at", "")
    st.session_state.pop("pending_registration", None)


def effacer_session_authentifiee() -> None:
    for key in (
        "auth_token",
        "auth_user",
        "auth_expires_at",
        "pending_registration",
        "pending_profile_email",
        "pending_password_reset_email",
    ):
        st.session_state.pop(key, None)


def afficher_portail_authentification() -> bool:
    """Bloque l'application tant qu'une session API valide n'est pas ouverte."""
    token = str(st.session_state.get("auth_token", "")).strip()
    if token:
        try:
            me_response = get_api("/auth/me", timeout=(2.5, 8.0))
            if me_response.status_code == 200:
                st.session_state["auth_user"] = me_response.json().get("user", {})
                return True
            if me_response.status_code == 401:
                effacer_session_authentifiee()
        except requests.RequestException:
            st.error("L'API d'authentification est temporairement indisponible.")
            return False

    try:
        status_response = requests.get(f"{API_URL}/auth/status", timeout=(2.5, 8.0))
        status_payload = status_response.json() if status_response.status_code == 200 else {}
    except requests.RequestException:
        status_payload = {}

    _, auth_column, _ = st.columns([0.55, 1.35, 0.55])
    with auth_column:
        render_page_header(
            "Accès sécurisé",
            "Supervision des cyberattaques",
            "Connectez-vous pour accéder aux analyses, aux alertes Suricata et au registre des incidents.",
        )

        auth_flash = str(st.session_state.pop("auth_flash", "")).strip()
        if auth_flash:
            st.success(auth_flash)

        tab_login, tab_register = st.tabs(["Connexion", "Inscription"])

        with tab_login:
            with st.form("auth_login_form"):
                identifier = st.text_input(
                    "Identifiant ou adresse e-mail",
                    placeholder="analyste ou analyste@exemple.com",
                )
                password = st.text_input(
                    "Mot de passe",
                    type="password",
                    placeholder="Votre mot de passe",
                )
                login_submitted = st.form_submit_button(
                    "Se connecter",
                    type="primary",
                    use_container_width=True,
                )

            if login_submitted:
                if not identifier.strip() or not password:
                    st.error("Renseignez votre identifiant et votre mot de passe.")
                else:
                    try:
                        response = requests.post(
                            f"{API_URL}/auth/login",
                            json={"identifier": identifier.strip(), "password": password},
                            timeout=20,
                        )
                        if response.status_code == 200:
                            enregistrer_session_authentifiee(response.json())
                            st.rerun()
                        else:
                            st.error(api_error_detail(response))
                    except requests.RequestException:
                        st.error("Impossible de joindre le service d'authentification.")

            with st.expander("Mot de passe oublié"):
                reset_email = str(
                    st.session_state.get("pending_password_reset_email", "")
                ).strip()
                if not reset_email:
                    with st.form("password_reset_request_form"):
                        requested_email = st.text_input(
                            "Adresse e-mail vérifiée",
                            placeholder="analyste.securite@gmail.com",
                        )
                        reset_request_submitted = st.form_submit_button(
                            "Recevoir un code de réinitialisation",
                            use_container_width=True,
                        )
                    if reset_request_submitted:
                        if not requested_email.strip():
                            st.error("Renseignez votre adresse e-mail.")
                        else:
                            try:
                                response = request_password_reset_code(
                                    requested_email.strip().lower()
                                )
                                if response.status_code == 200:
                                    st.session_state[
                                        "pending_password_reset_email"
                                    ] = requested_email.strip().lower()
                                    st.info(
                                        response.json().get(
                                            "message",
                                            "Si le compte existe, un code a été envoyé.",
                                        )
                                    )
                                    st.rerun()
                                else:
                                    st.error(api_error_detail(response))
                            except requests.RequestException:
                                st.error("Le service de réinitialisation est indisponible.")
                else:
                    st.info(
                        "Si l'adresse correspond à un compte vérifié, saisissez le code reçu."
                    )
                    with st.form("password_reset_verify_form"):
                        reset_code = st.text_input(
                            "Code à 6 chiffres",
                            max_chars=6,
                            placeholder="000000",
                        )
                        reset_password = st.text_input(
                            "Nouveau mot de passe",
                            type="password",
                            help="10 caractères minimum, avec majuscule, minuscule et chiffre.",
                        )
                        reset_confirmation = st.text_input(
                            "Confirmer le nouveau mot de passe",
                            type="password",
                        )
                        reset_verify_submitted = st.form_submit_button(
                            "Réinitialiser le mot de passe",
                            type="primary",
                            use_container_width=True,
                        )
                    if reset_verify_submitted:
                        if reset_password != reset_confirmation:
                            st.error("Les deux mots de passe ne correspondent pas.")
                        elif len(reset_code.strip()) != 6 or not reset_code.strip().isdigit():
                            st.error("Saisissez exactement les 6 chiffres reçus.")
                        else:
                            try:
                                response = verify_password_reset_code(
                                    reset_email,
                                    reset_code.strip(),
                                    reset_password,
                                )
                                if response.status_code == 200:
                                    st.session_state.pop(
                                        "pending_password_reset_email",
                                        None,
                                    )
                                    st.success(response.json().get("message", "Mot de passe modifié."))
                                else:
                                    st.error(api_error_detail(response))
                            except requests.RequestException:
                                st.error("La vérification du code est indisponible.")
                    if st.button(
                        "Recommencer la récupération",
                        key="password_reset_restart",
                        use_container_width=True,
                    ):
                        st.session_state.pop("pending_password_reset_email", None)
                        st.rerun()

        with tab_register:
            registration_enabled = bool(status_payload.get("registration_enabled", False))
            if not registration_enabled:
                st.info(
                    "Le compte principal existe déjà. L'inscription publique est fermée "
                    "pour empêcher la création de comptes non autorisés."
                )
            pending = st.session_state.get("pending_registration")
            if pending:
                st.success(
                    "Un code à 6 chiffres a été envoyé à "
                    f"{pending.get('email_masked', 'votre adresse e-mail')}."
                )
                st.caption(
                    "Le compte sera activé uniquement après vérification du code. "
                    "Le code expire après 10 minutes."
                )
                with st.form("auth_registration_code_form"):
                    verification_code = st.text_input(
                        "Code de vérification",
                        max_chars=6,
                        placeholder="000000",
                    )
                    verify_submitted = st.form_submit_button(
                        "Vérifier et créer le compte",
                        type="primary",
                        use_container_width=True,
                    )

                if verify_submitted:
                    code = verification_code.strip()
                    if len(code) != 6 or not code.isdigit():
                        st.error("Saisissez exactement les 6 chiffres reçus par e-mail.")
                    else:
                        try:
                            response = requests.post(
                                f"{API_URL}/auth/register/verify",
                                json={
                                    "registration_id": pending["registration_id"],
                                    "code": code,
                                },
                                timeout=20,
                            )
                            if response.status_code == 200:
                                enregistrer_session_authentifiee(response.json())
                                st.rerun()
                            else:
                                st.error(api_error_detail(response))
                        except requests.RequestException:
                            st.error("La vérification du code est momentanément indisponible.")

                resend_column, restart_column = st.columns(2)
                with resend_column:
                    if st.button(
                        "Renvoyer le code",
                        use_container_width=True,
                        key="registration_resend",
                    ):
                        try:
                            response = requests.post(
                                f"{API_URL}/auth/register/resend",
                                json={"registration_id": pending["registration_id"]},
                                timeout=25,
                            )
                            if response.status_code == 200:
                                st.success("Un nouveau code a été envoyé.")
                            else:
                                st.error(api_error_detail(response))
                        except requests.RequestException:
                            st.error("Le code n'a pas pu être renvoyé.")
                with restart_column:
                    if st.button(
                        "Recommencer",
                        use_container_width=True,
                        key="registration_restart",
                    ):
                        st.session_state.pop("pending_registration", None)
                        st.rerun()
            else:
                if status_payload and not status_payload.get(
                    "email_verification_available",
                    False,
                ):
                    st.warning(
                        "L'inscription nécessite la configuration Gmail du fichier .env "
                        "afin d'envoyer le code de vérification."
                    )

                with st.form("auth_registration_form"):
                    full_name = st.text_input(
                        "Nom complet",
                        placeholder="Prénom NOM",
                        disabled=not registration_enabled,
                    )
                    username = st.text_input(
                        "Identifiant",
                        placeholder="analyste_soc",
                        disabled=not registration_enabled,
                    )
                    email = st.text_input(
                        "E-mail de réception des alertes",
                        placeholder="analyste.securite@gmail.com",
                        disabled=not registration_enabled,
                    )
                    registration_password = st.text_input(
                        "Mot de passe",
                        type="password",
                        help="10 caractères minimum, avec majuscule, minuscule et chiffre.",
                        disabled=not registration_enabled,
                    )
                    confirmation_password = st.text_input(
                        "Confirmer le mot de passe",
                        type="password",
                        disabled=not registration_enabled,
                    )
                    register_submitted = st.form_submit_button(
                        "Recevoir le code de vérification",
                        type="primary",
                        use_container_width=True,
                        disabled=not registration_enabled,
                    )

                if register_submitted:
                    if registration_password != confirmation_password:
                        st.error("Les deux mots de passe ne correspondent pas.")
                    elif not all(
                        [
                            full_name.strip(),
                            username.strip(),
                            email.strip(),
                            registration_password,
                        ]
                    ):
                        st.error("Complétez tous les champs de l'inscription.")
                    else:
                        try:
                            response = requests.post(
                                f"{API_URL}/auth/register/request-code",
                                json={
                                    "full_name": full_name.strip(),
                                    "username": username.strip(),
                                    "email": email.strip(),
                                    "password": registration_password,
                                },
                                timeout=30,
                            )
                            if response.status_code == 200:
                                result = response.json()
                                st.session_state["pending_registration"] = {
                                    "registration_id": result["registration_id"],
                                    "email_masked": result.get("email_masked", ""),
                                }
                                st.rerun()
                            else:
                                st.error(api_error_detail(response))
                        except requests.RequestException:
                            st.error("Le code de vérification n'a pas pu être envoyé.")
    return False


if not afficher_portail_authentification():
    st.stop()


st.sidebar.markdown(
    f"""
    <div class="soc-brand">
        <div class="soc-brand__emblem" aria-hidden="true">
            <svg viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M32 5L53 13V29C53 43 44.5 53.5 32 59C19.5 53.5 11 43 11 29V13L32 5Z"
                      stroke="#69EEFF" stroke-width="3" fill="rgba(57,231,255,.07)"/>
                <path d="M23 33L29 39L42 24" stroke="#FFFFFF" stroke-width="4"
                      stroke-linecap="round" stroke-linejoin="round"/>
                <circle cx="18" cy="20" r="2" fill="#8A5CFF"/>
                <circle cx="46" cy="37" r="2" fill="#39E7FF"/>
                <path d="M18 22V28H23M46 35V29H42" stroke="#7DDFFF" stroke-width="1.8"
                      stroke-linecap="round"/>
            </svg>
        </div>
        <div class="soc-brand__copy">
            <span class="soc-brand__name">Supervision des cyberattaques</span>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

auth_user = st.session_state.get("auth_user", {})
st.sidebar.markdown(
    f"""
    <div class="soc-sidebar-footer">
        <div class="soc-sidebar-footer__status">Session sécurisée</div>
        <div class="soc-sidebar-footer__meta">
            {escape(str(auth_user.get('full_name', auth_user.get('username', 'Utilisateur'))))}<br>
            {escape(str(auth_user.get('email_masked', 'E-mail non configuré')))}
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)
if st.sidebar.button("Se déconnecter", use_container_width=True):
    try:
        requests.post(
            f"{API_URL}/auth/logout",
            headers=auth_headers(),
            timeout=8,
        )
    except requests.RequestException:
        pass
    effacer_session_authentifiee()
    st.rerun()

page = st.sidebar.radio(
    "Navigation principale",
    [
        PAGE_DASHBOARD,
        PAGE_DETECTION,
        PAGE_NOTIFICATIONS,
        PAGE_HISTORY,
        PAGE_PROFILE,
    ],
    format_func=lambda valeur: NAVIGATION_LABELS.get(valeur, valeur),
    label_visibility="collapsed",
)

if page == PAGE_DASHBOARD:
    render_page_header(
        "Supervision opérationnelle",
        "Tableau de bord opérationnel",
        "Vue consolidée des prédictions d'attaque, du niveau de risque, des alertes "
        "et de l'évolution de l'activité réseau.",
    )

    if st.session_state.pop("traffic_reset_success", False):
        st.success("Le volume de trafic analysé a été remis à zéro.")

    try:
        with st.spinner("Synchronisation des données de supervision…"):
            api_responses, erreurs_api = get_api_batch(
                {
                    "statistiques": "/stats",
                    "historique": "/history",
                    "notifications": "/notifications",
                    "modele": "/model-status",
                }
            )

        api_payloads: dict[str, dict] = {}
        for cle, response in api_responses.items():
            if response.status_code != 200:
                erreurs_api[cle] = f"Code HTTP {response.status_code}"
                continue
            try:
                payload = response.json()
            except ValueError:
                erreurs_api[cle] = "Réponse JSON invalide"
                continue
            if isinstance(payload, dict):
                api_payloads[cle] = payload
            else:
                erreurs_api[cle] = "Format de réponse inattendu"

        if erreurs_api:
            modules_indisponibles = ", ".join(
                NAVIGATION_LABELS.get(cle, cle).capitalize()
                for cle in sorted(erreurs_api)
            )
            st.warning(
                "Certaines données ne sont pas disponibles pour le moment : "
                f"{modules_indisponibles}. L'interface reste utilisable."
            )

        stats = api_payloads.get("statistiques", {})
        historique_brut = api_payloads.get("historique", {}).get("history", [])
        notifications_payload = api_payloads.get("notifications", {})
        notifications_brutes = notifications_payload.get("notifications", [])
        model_payload = api_payloads.get("modele")
        stats_disponibles = "statistiques" in api_payloads
        historique_disponible = "historique" in api_payloads
        notifications_disponibles = "notifications" in api_payloads

        historique = preparer_historique(historique_brut)

        filtre_col1, filtre_col2 = st.columns([1, 3])
        with filtre_col1:
            periode_selectionnee = st.selectbox(
                "Période d'observation",
                list(PERIOD_OPTIONS.keys()),
                index=0,
                help=(
                    "Le filtre s'applique aux événements historisés et aux séries "
                    "temporelles disponibles."
                ),
            )
        with filtre_col2:
            st.markdown(
                "<div style='height:29px'></div>",
                unsafe_allow_html=True,
            )
            st.caption(
                "Les indicateurs sont recalculés à partir des compteurs persistants, "
                "du registre des incidents et des alertes récentes."
            )

        historique_filtre = filtrer_historique_par_periode(
            historique,
            periode_selectionnee,
        )
        serie_temporelle = filtrer_serie_par_periode(
            construire_serie_temporelle(stats, historique),
            periode_selectionnee,
        )

        attaques_historisees = int(
            historique_filtre.loc[
                ~historique_filtre.get(
                    "_est_benin",
                    pd.Series(False, index=historique_filtre.index),
                ),
                "_occurrences",
            ].sum()
        ) if not historique_filtre.empty else 0

        if periode_selectionnee == "Toutes les données":
            if historique_disponible or stats_disponibles:
                attaques_detectees = attaques_historisees or int(
                    stats.get("attaques_detectees", stats.get("total_alertes", 0)) or 0
                )
            else:
                attaques_detectees = None

            if stats_disponibles or notifications_disponibles:
                alertes_declenchees = int(
                    stats.get(
                        "alertes_declenchees",
                        stats.get(
                            "total_alertes",
                            notifications_payload.get("total_notifications", 0),
                        ),
                    )
                    or 0
                )
            else:
                alertes_declenchees = None
        else:
            attaques_detectees = attaques_historisees if historique_disponible else None
            alertes_declenchees = (
                int(len(historique_filtre)) if historique_disponible else None
            )

        if periode_selectionnee == "Toutes les données":
            volume_trafic = (
                int(stats.get("flux_reseau_analyses", 0) or 0)
                if stats_disponibles
                else None
            )
            libelle_volume = "Volume de trafic analysé"
        elif not serie_temporelle.empty and serie_temporelle["Trafic bénin"].sum() > 0:
            volume_trafic = int(
                serie_temporelle[["Trafic bénin", "Trafic malveillant"]].sum().sum()
            )
            libelle_volume = "Trafic sur la période"
        else:
            volume_trafic = (
                int(stats.get("flux_reseau_analyses", 0) or 0)
                if stats_disponibles
                else None
            )
            libelle_volume = "Volume cumulé analysé"

        risque = stats.get("risque_global", {}) or {}

        render_section_heading(
            "Indicateurs clés de sécurité",
            "Synthèse du trafic traité, des attaques prédites, des alertes et du risque global.",
        )
        kpi1, kpi2, kpi3, kpi4 = st.columns(4, gap="large")

        with kpi1:
            valeur_volume = (
                f"{formater_nombre(volume_trafic)} flux"
                if volume_trafic is not None
                else "—"
            )
            st.metric(
                libelle_volume,
                valeur_volume,
                help="Nombre de flux réseau traités par le moteur de détection.",
            )
            if periode_selectionnee == "Toutes les données":
                if st.button(
                    "Réinitialiser le volume",
                    key="request_traffic_reset",
                    use_container_width=True,
                    help=(
                        "Remet uniquement ce compteur à zéro, sans supprimer les "
                        "alertes ni l'historique."
                    ),
                ):
                    render_traffic_reset_dialog()
        with kpi2:
            st.metric(
                "Nombre d'attaques détectées",
                formater_nombre(attaques_detectees),
                help="Somme des occurrences classées comme malveillantes.",
            )
        with kpi3:
            st.metric(
                "Nombre d'alertes déclenchées",
                formater_nombre(alertes_declenchees),
                help="Nombre d'alertes opérationnelles générées et placées dans le centre de traitement.",
            )
        with kpi4:
            with st.container(border=True):
                render_risk_gauge(risque)

        render_section_heading(
            "État du système en quasi temps réel",
            "Disponibilité des services essentiels de détection et de notification.",
        )
        render_system_status_live()

        render_section_heading(
            "Évolution temporelle du trafic",
            "Comparaison du trafic bénin et malveillant avec mise en évidence des pics suspects.",
        )
        with st.container(border=True):
            render_time_series_chart(serie_temporelle)

        render_section_heading(
            "Répartition des détections",
            "Lecture des catégories d'attaques prédites et de leur niveau de sévérité.",
        )
        repartition_col1, repartition_col2 = st.columns(2, gap="large")

        with repartition_col1:
            with st.container(border=True):
                repartition_attaques = extraire_repartition_attaques(
                    stats if periode_selectionnee == "Toutes les données" else {},
                    historique_filtre,
                )
                render_donut_chart(
                    repartition_attaques,
                    "Type de menace",
                    "Occurrences",
                    "Répartition par type d'attaque",
                    "Principales classes malveillantes détectées par la plateforme",
                )

        with repartition_col2:
            with st.container(border=True):
                par_gravite = (
                    stats.get("par_gravite", {}) or {}
                    if periode_selectionnee == "Toutes les données"
                    else {}
                )
                if par_gravite:
                    repartition_gravite = dataframe_from_dict_counter(
                        par_gravite,
                        "Niveau de sévérité",
                    )
                elif not historique_filtre.empty and "gravite" in historique_filtre.columns:
                    repartition_gravite = (
                        historique_filtre.groupby("gravite", dropna=False)["_occurrences"]
                        .sum()
                        .reset_index()
                        .rename(
                            columns={
                                "gravite": "Niveau de sévérité",
                                "_occurrences": "Volume d'événements",
                            }
                        )
                    )
                    repartition_gravite["Niveau de sévérité"] = repartition_gravite[
                        "Niveau de sévérité"
                    ].map(libelle_professionnel)
                else:
                    repartition_gravite = pd.DataFrame()

                if repartition_gravite.empty:
                    st.info("Aucune donnée disponible par niveau de sévérité.")
                else:
                    render_donut_chart(
                        repartition_gravite,
                        "Niveau de sévérité",
                        "Volume d'événements",
                        "Répartition par sévérité",
                        "Poids relatif des incidents selon leur criticité",
                        {
                            "Critique": "#B42318",
                            "Élevée": "#F04438",
                            "Moyenne": "#F79009",
                            "Faible": "#12B76A",
                        },
                    )

        render_section_heading(
            "Activité opérationnelle récente",
            "Dernières prédictions enregistrées et état de transmission des alertes.",
        )
        recent_col1, recent_col2 = st.columns([1.35, 1], gap="large")

        with recent_col1:
            with st.container(border=True):
                st.markdown("#### Journal des événements récents")
                st.caption(
                    "Horodatage, adresses réseau, menace prédite, risque associé et statut de traitement."
                )
                evenements_recents = preparer_evenements_recents(
                    historique_filtre,
                    limite=8,
                )
                if not historique_disponible:
                    st.info(
                        "Le journal des événements apparaîtra dès que le registre "
                        "sera de nouveau accessible."
                    )
                elif evenements_recents.empty:
                    st.info("Aucun événement n'est disponible pour la période sélectionnée.")
                else:
                    st.dataframe(
                        styliser_tableau_soc(evenements_recents),
                        use_container_width=True,
                        hide_index=True,
                        height=315,
                    )

        with recent_col2:
            with st.container(border=True):
                st.markdown("#### Panneau des alertes")
                st.caption(
                    "Alertes récentes et état de transmission par messagerie électronique."
                )

                alertes_recentes = preparer_alertes_recentes(
                    notifications_brutes,
                    historique_filtre,
                    limite=6,
                )

                if not notifications_disponibles and not historique_disponible:
                    st.info(
                        "Le panneau des alertes apparaîtra dès que les données "
                        "opérationnelles seront accessibles."
                    )
                elif alertes_recentes.empty:
                    st.success("Aucune alerte récente n'est en attente de traitement.")
                else:
                    st.dataframe(
                        styliser_tableau_soc(alertes_recentes),
                        use_container_width=True,
                        hide_index=True,
                        height=255,
                    )

                    if "État de notification" in alertes_recentes.columns:
                        statuts_notification = alertes_recentes[
                            "État de notification"
                        ].astype(str)
                        transmises = int(
                            statuts_notification.isin(["Transmis", "Envoyée", "Envoyé"]).sum()
                        )
                        echecs = int((statuts_notification == "Échec").sum())
                        panel_metric1, panel_metric2 = st.columns(2)
                        with panel_metric1:
                            st.metric("Transmises", transmises)
                        with panel_metric2:
                            st.metric("Échecs", echecs)

        render_section_heading(
            "État du moteur d'intelligence artificielle",
            "Disponibilité et niveau de performance du modèle de classification chargé.",
        )

        if model_payload is not None:
            model = model_payload
            modele_charge = bool(
                model.get("model_loaded", model.get("model_found", False))
            )
            mode_secours = bool(
                model.get("fallback_active", not modele_charge)
            )
            moteur_disponible = bool(
                model.get(
                    "engine_available",
                    modele_charge or mode_secours,
                )
            )

            if modele_charge:
                nom_modele = model.get("model_name") or "Modèle de classification"
                score_modele = (
                    model.get("score")
                    if model.get("score") is not None
                    else "Non renseigné"
                )
            else:
                nom_modele = "Mode de secours (règles/labels)"
                score_modele = "Non applicable"

            model_col1, model_col2, model_col3 = st.columns(3)
            with model_col1:
                st.metric(
                    "Disponibilité du moteur",
                    "Opérationnel" if moteur_disponible else "Indisponible",
                )
            with model_col2:
                st.metric(
                    "Mode actif",
                    nom_modele,
                )
            with model_col3:
                st.metric("Score de référence", score_modele)

            if mode_secours and model.get("load_error"):
                st.warning(f"Diagnostic du modèle : {model['load_error']}")
            elif mode_secours:
                st.info(
                    "Le moteur reste utilisable en mode de secours. Le modèle "
                    "entraîné sera sélectionné automatiquement dès qu'il sera chargé."
                )
        else:
            st.info(
                "Les informations du modèle apparaîtront dès que le service "
                "de classification sera disponible."
            )

    except Exception as exc:  # noqa: BLE001
        st.warning("Le service central d'analyse est actuellement indisponible.")
        with st.expander("Consulter les détails techniques"):
            st.code(str(exc))

elif page == PAGE_DETECTION:
    render_page_header(
        "Détection et qualification",
        "Opérations de détection",
        "Espace unifié d'analyse des flux réseau et de qualification des événements "
        "de sécurité produits par l'IDS Suricata.",
    )

    onglet_csv, onglet_suricata = st.tabs(
        [
            "Détection IA sur flux réseau",
            "Triage des événements Suricata",
        ]
    )

    with onglet_csv:
        render_section_heading(
            "Détection IA sur flux réseau",
            "Importation et classification des flux compatibles avec la structure "
            "du jeu de données CIC-IDS2017.",
        )

        uploaded_csv = st.file_uploader(
            "Sélectionner un jeu de flux réseau au format CSV",
            type=["csv"],
            key="csv_threat_analysis_uploader",
            help="Le fichier doit contenir les variables attendues par le moteur de classification.",
        )
        st.caption(
            "Format accepté : CSV · Taille maximale actuelle : 200 Mo · "
            "Pour la démonstration, utilisez un extrait représentatif."
        )

        st.info(
            "Toute détection malveillante est enregistrée dans le registre et transmise "
            "automatiquement au destinataire configuré."
        )

        if uploaded_csv is None:
            st.info("En attente d'un fichier de flux réseau à analyser.")
        else:
            st.success(f"Jeu de flux chargé : {uploaded_csv.name}")

            if st.button(
                "Exécuter la détection IA",
                key="analyze_csv_button",
                type="primary",
            ):
                files = {
                    "file": (
                        uploaded_csv.name,
                        uploaded_csv.getvalue(),
                        "text/csv",
                    )
                }
                try:
                    response = requests.post(
                        f"{API_URL}/analyze",
                        files=files,
                        headers=auth_headers(),
                        timeout=120,
                    )

                    if response.status_code == 200:
                        result = response.json()

                        render_section_heading(
                            "Synthèse de l'analyse",
                            "Indicateurs produits par le moteur de classification.",
                        )

                        col1, col2, col3, col4 = st.columns(4)

                        with col1:
                            st.metric("Flux examinés", result["total_flux"])
                        with col2:
                            st.metric("Variables exploitées", result["total_colonnes"])
                        with col3:
                            st.metric("Flux malveillants", result["attaques_detectees"])
                        with col4:
                            st.metric(
                                "Alertes transmises",
                                result.get("notifications_envoyees", 0),
                            )

                        st.caption(
                            f"Élément analysé : {result['filename']} · "
                            f"Moteur utilisé : {result['mode_analyse']}"
                        )

                        model = result.get("model", {})
                        with st.expander("Informations sur le moteur de classification"):
                            st.write(
                                "**Disponibilité :**",
                                "Opérationnel" if model.get("model_found") else "Indisponible",
                            )
                            st.write(
                                "**Modèle actif :**",
                                model.get("model_name", "Non identifié"),
                            )
                            st.write(
                                "**Score de référence :**",
                                model.get("score", "Non disponible"),
                            )
                            if model.get("load_error"):
                                st.warning(model["load_error"])

                        if result["details_classes"]:
                            df_details = pd.DataFrame(result["details_classes"])
                            render_section_heading(
                                "Menaces identifiées",
                                "Qualification, sévérité et mesure de réponse recommandée.",
                            )
                            st.dataframe(
                                styliser_tableau_soc(dataframe_professionnel(df_details)),
                                use_container_width=True,
                                hide_index=True,
                            )

                            render_section_heading(
                                "Répartition des détections",
                                "Volume observé pour chaque type de menace identifié.",
                            )
                            df_distribution = dataframe_from_dict_counter(
                                result["distribution_classes"],
                                "Type de trafic",
                            )
                            st.bar_chart(df_distribution.set_index("Type de trafic"))

                            st.success(
                                "Analyse terminée : les détections ont été enregistrées "
                                "et qualifiées."
                            )
                        else:
                            st.success(
                                "Aucun comportement malveillant n'a été identifié dans ce jeu de flux."
                            )

                        afficher_resume_notifications(
                            result.get("notification_summary", {})
                        )
                    else:
                        afficher_erreur_api(response)

                except Exception as exc:  # noqa: BLE001
                    st.error("Le service de détection IA est actuellement indisponible.")
                    with st.expander("Consulter les détails techniques"):
                        st.code(str(exc))

    with onglet_suricata:
        render_section_heading(
            "Surveillance continue des événements Suricata",
            "Lecture incrémentale de eve.json, qualification automatique et "
            "enregistrement immédiat dans le registre.",
        )

        render_suricata_monitor_live()

        st.divider()
        render_section_heading(
            "Import manuel de secours",
            "Cette option reste disponible pour analyser un ancien journal ou "
            "effectuer un contrôle ponctuel.",
        )

        uploaded_suricata = st.file_uploader(
            "Sélectionner un journal d'événements Suricata (eve.json)",
            type=["json"],
            key="suricata_alert_uploader",
            help="Le fichier attendu est le journal JSON produit par Suricata.",
        )
        st.caption(
            "Format accepté : JSON (eve.json) · Taille maximale actuelle : 200 Mo · "
            "Le fichier reste sous contrôle de l'utilisateur jusqu'au lancement du triage."
        )

        st.info(
            "Les événements qualifiés sont enregistrés dans le registre et les alertes "
            "prioritaires sont transmises automatiquement."
        )

        if uploaded_suricata is None:
            st.info("En attente d'un journal Suricata à qualifier.")
        else:
            st.success(f"Journal IDS chargé : {uploaded_suricata.name}")

            if st.button(
                "Exécuter le triage IDS",
                key="analyze_suricata_button",
                type="primary",
            ):
                files = {
                    "file": (
                        uploaded_suricata.name,
                        uploaded_suricata.getvalue(),
                        "application/json",
                    )
                }
                try:
                    response = requests.post(
                        f"{API_URL}/analyze-suricata",
                        files=files,
                        headers=auth_headers(),
                        timeout=120,
                    )

                    if response.status_code == 200:
                        result = response.json()

                        render_section_heading(
                            "Synthèse du triage IDS",
                            "Volume d'événements qualifiés et état de diffusion des alertes.",
                        )

                        col1, col2 = st.columns(2)
                        with col1:
                            st.metric(
                                "Nouveaux événements enregistrés",
                                result.get(
                                    "nouvelles_alertes",
                                    result["total_alertes"],
                                ),
                            )
                        with col2:
                            st.metric(
                                "Alertes transmises",
                                result.get("notifications_envoyees", 0),
                            )

                        st.caption(f"Journal analysé : {result['filename']}")
                        if result.get("doublons_ignores", 0):
                            st.info(
                                f"{result['doublons_ignores']} événement(s) déjà "
                                "présent(s) ont été ignorés."
                            )

                        if result["alertes"]:
                            df_alertes = pd.DataFrame(result["alertes"]).drop(
                                columns=["event_id"],
                                errors="ignore",
                            )
                            render_section_heading(
                                "Événements de sécurité qualifiés",
                                "Données réseau, signature IDS, niveau de sévérité et réponse recommandée.",
                            )
                            st.dataframe(
                                styliser_tableau_soc(dataframe_professionnel(df_alertes)),
                                use_container_width=True,
                                hide_index=True,
                            )
                            st.success(
                                "Triage terminé : les événements IDS ont été enregistrés "
                                "et qualifiés."
                            )
                        else:
                            st.success(
                                "Aucun événement de sécurité exploitable n'a été identifié "
                                "dans ce journal."
                            )

                        afficher_resume_notifications(
                            result.get("notification_summary", {})
                        )
                    else:
                        afficher_erreur_api(response)

                except Exception as exc:  # noqa: BLE001
                    st.error("Le service de triage IDS est actuellement indisponible.")
                    with st.expander("Consulter les détails techniques"):
                        st.code(str(exc))


elif page == PAGE_PROFILE:
    render_page_header(
        "Compte et paramètres de diffusion",
        "Profil sécurisé",
        "Gestion du compte authentifié et de l'adresse vérifiée qui reçoit les alertes "
        "de cybersécurité.",
    )

    try:
        profile_response = get_api("/profile")

        if profile_response.status_code == 200:
            profile = profile_response.json()

            render_section_heading(
                "Informations du compte",
                "La session et les données du destinataire sont associées à cet utilisateur.",
            )
            account_col1, account_col2, account_col3 = st.columns(3)
            with account_col1:
                st.metric("Utilisateur", profile.get("full_name", "—"))
            with account_col2:
                st.metric("Identifiant", profile.get("username", "—"))
            with account_col3:
                st.metric(
                    "E-mail d'alerte",
                    "Vérifié" if profile.get("email_verified") else "Non vérifié",
                )

            if profile.get("email_verified") and profile.get("email_masked"):
                st.success(
                    "Destinataire actif et vérifié : "
                    f"{profile['email_masked']}. Les alertes peuvent être transmises."
                )
            else:
                st.warning(
                    "Aucune adresse vérifiée n'est active. Les notifications ne seront "
                    "pas envoyées à ce compte avant la validation du code."
                )

            render_section_heading(
                "Vérification de l'adresse de réception",
                "Un changement d'adresse n'est appliqué qu'après saisie du code reçu par e-mail.",
            )

            pending_email = str(
                st.session_state.get("pending_profile_email", "")
            ).strip()

            if pending_email:
                st.info(
                    "Saisissez le code à 6 chiffres envoyé à cette adresse. "
                    "L'ancienne adresse reste active jusqu'à la validation."
                )
                with st.form("profile_email_code_form"):
                    profile_code = st.text_input(
                        "Code de vérification",
                        max_chars=6,
                        placeholder="000000",
                    )
                    verify_email = st.form_submit_button(
                        "Vérifier et activer l'adresse",
                        type="primary",
                        use_container_width=True,
                    )

                if verify_email:
                    code = profile_code.strip()
                    if len(code) != 6 or not code.isdigit():
                        st.error("Le code doit contenir exactement 6 chiffres.")
                    else:
                        verify_response = verify_profile_email_code(pending_email, code)
                        if verify_response.status_code == 200:
                            result = verify_response.json()
                            st.session_state["auth_user"] = result.get("user", profile)
                            st.session_state.pop("pending_profile_email", None)
                            st.success(
                                "Adresse vérifiée. Les prochaines alertes seront envoyées à "
                                f"{result['user']['email_masked']}."
                            )
                        else:
                            st.error(api_error_detail(verify_response))

                resend_col, cancel_col = st.columns(2)
                with resend_col:
                    if st.button(
                        "Renvoyer le code",
                        key="profile_resend_code",
                        use_container_width=True,
                    ):
                        resend_response = request_profile_email_code(pending_email)
                        if resend_response.status_code == 200:
                            st.success("Un nouveau code a été envoyé.")
                        else:
                            st.error(api_error_detail(resend_response))
                with cancel_col:
                    if st.button(
                        "Annuler le changement",
                        key="profile_cancel_email",
                        use_container_width=True,
                    ):
                        st.session_state.pop("pending_profile_email", None)
                        st.rerun()
            else:
                with st.form("profile_email_form"):
                    nouvel_email = st.text_input(
                        "Nouvelle adresse de réception",
                        value="",
                        placeholder="analyste.securite@gmail.com",
                    )
                    confirmation_email = st.text_input(
                        "Confirmer la nouvelle adresse",
                        value="",
                        placeholder="analyste.securite@gmail.com",
                    )
                    envoyer_code = st.form_submit_button(
                        "Envoyer le code de vérification",
                        type="primary",
                        use_container_width=True,
                    )

                if envoyer_code:
                    nouvel_email = nouvel_email.strip().lower()
                    confirmation_email = confirmation_email.strip().lower()
                    if not nouvel_email:
                        st.error("Renseignez une adresse de réception.")
                    elif nouvel_email != confirmation_email:
                        st.error("Les deux adresses ne correspondent pas.")
                    else:
                        code_response = request_profile_email_code(nouvel_email)
                        if code_response.status_code == 200:
                            result = code_response.json()
                            st.session_state["pending_profile_email"] = nouvel_email
                            st.success(
                                "Code envoyé à "
                                f"{result.get('email_masked', 'la nouvelle adresse')}."
                            )
                            st.rerun()
                        else:
                            st.error(api_error_detail(code_response))

            render_section_heading(
                "Sécurité du mot de passe",
                "Le changement ferme immédiatement toutes les sessions actives du compte.",
            )
            with st.form("profile_password_change_form"):
                current_password = st.text_input(
                    "Mot de passe actuel",
                    type="password",
                )
                new_password = st.text_input(
                    "Nouveau mot de passe",
                    type="password",
                    help="10 caractères minimum, avec majuscule, minuscule et chiffre.",
                )
                new_password_confirmation = st.text_input(
                    "Confirmer le nouveau mot de passe",
                    type="password",
                )
                password_change_submitted = st.form_submit_button(
                    "Modifier le mot de passe",
                    type="primary",
                    use_container_width=True,
                )

            if password_change_submitted:
                if new_password != new_password_confirmation:
                    st.error("Les deux nouveaux mots de passe ne correspondent pas.")
                elif not current_password or not new_password:
                    st.error("Complétez les trois champs du mot de passe.")
                else:
                    password_response = change_account_password(
                        current_password,
                        new_password,
                    )
                    if password_response.status_code == 200:
                        effacer_session_authentifiee()
                        st.session_state["auth_flash"] = (
                            "Mot de passe modifié. Reconnectez-vous avec le nouveau mot de passe."
                        )
                        st.rerun()
                    else:
                        st.error(api_error_detail(password_response))

            with st.expander("Journal de sécurité du compte"):
                security_response = get_api("/profile/security-events")
                if security_response.status_code == 200:
                    security_events = security_response.json().get("events", [])
                    if security_events:
                        st.dataframe(
                            dataframe_professionnel(pd.DataFrame(security_events)),
                            use_container_width=True,
                            hide_index=True,
                        )
                    else:
                        st.info("Aucun événement de sécurité enregistré.")
                else:
                    st.error(api_error_detail(security_response))
        else:
            afficher_erreur_api(profile_response)

    except Exception as exc:  # noqa: BLE001
        st.error("Le service de gestion du destinataire est actuellement indisponible.")
        with st.expander("Consulter les détails techniques"):
            st.code(str(exc))


elif page == PAGE_NOTIFICATIONS:
    render_page_header(
        "Qualification et réponse",
        "Centre de traitement des alertes",
        "Pilotage des événements prioritaires, contrôle du canal de diffusion et suivi "
        "des actions de traitement.",
    )

    try:
        config_response = get_api("/notification-config")
        response = get_api("/notifications")

        if config_response.status_code == 200:
            config = config_response.json()
            render_section_heading(
                "État du canal de diffusion",
                "Contrôle de disponibilité de la passerelle de messagerie utilisée pour les alertes.",
            )
            gmail_ok = config["gmail"]["enabled"] and config["gmail"]["configured"]
            st.metric(
                "Passerelle de messagerie Gmail",
                "Opérationnelle" if gmail_ok else "Configuration requise",
            )
            if config["gmail"].get("recipient"):
                st.caption(
                    f"Destinataire de sécurité actif : {config['gmail']['recipient']}"
                )

            if not gmail_ok:
                if not config["gmail"].get("smtp_configured"):
                    st.warning(
                        "La passerelle Gmail doit être configurée dans le fichier .env."
                    )
                elif not config["gmail"].get("email_verified"):
                    st.warning(
                        "Vérifiez votre adresse dans Profil sécurisé avant toute diffusion."
                    )

        else:
            afficher_erreur_api(config_response)

        if response.status_code == 200:
            result = response.json()
            notifications = result["notifications"]

            render_section_heading(
                "File des alertes prioritaires",
                "Événements critiques et élevés dont le traitement reste à confirmer.",
            )
            col1, col2, col3 = st.columns(3)

            with col1:
                st.metric("Alertes en attente", result["total_notifications"])
            with col2:
                st.metric("Priorité critique", result["critiques"])
            with col3:
                st.metric("Priorité élevée", result["elevees"])

            if notifications:
                df_notifications = pd.DataFrame(notifications)

                colonnes_cachees = [
                    "historique_id",
                    "message_notification",
                ]
                colonnes_affichage = [
                    col for col in df_notifications.columns
                    if col not in colonnes_cachees
                ]

                st.dataframe(
                    styliser_tableau_soc(dataframe_professionnel(df_notifications[colonnes_affichage])),
                    use_container_width=True,
                    hide_index=True,
                )

                def afficher_notification(historique_id: str) -> str:
                    ligne = df_notifications[
                        df_notifications["historique_id"] == historique_id
                    ].iloc[0]

                    return (
                        f"{libelle_professionnel(ligne['gravite'])} | "
                        f"{libelle_professionnel(ligne['source'])} | "
                        f"{ligne['classe']} | "
                        f"{ligne['date']}"
                    )

                notification_selectionnee = st.selectbox(
                    "Alerte à examiner",
                    df_notifications["historique_id"].tolist(),
                    format_func=afficher_notification,
                )

                ligne_selectionnee = df_notifications[
                    df_notifications["historique_id"] == notification_selectionnee
                ].iloc[0]

                render_section_heading(
                    "Contenu de l'alerte",
                    "Message opérationnel préparé pour la transmission au destinataire de sécurité.",
                )
                st.text_area(
                    "Message de sécurité généré",
                    ligne_selectionnee["message_notification"],
                    height=130,
                    disabled=True,
                )

                if st.button(
                    "Clôturer le traitement de cette alerte",
                    type="primary",
                ):
                    update_response = post_status(notification_selectionnee, "Traitee")

                    if update_response.status_code == 200:
                        st.success("Le traitement de l'alerte est désormais clôturé.")
                        st.rerun()
                    else:
                        afficher_erreur_api(update_response)
            else:
                st.success("Aucune alerte prioritaire n'est actuellement en attente.")
        else:
            afficher_erreur_api(response)

    except Exception as exc:  # noqa: BLE001
        st.error("Le service de traitement des alertes est actuellement indisponible.")
        with st.expander("Consulter les détails techniques"):
            st.code(str(exc))


elif page == PAGE_HISTORY:
    render_page_header(
        "Traçabilité et gouvernance",
        "Registre des incidents",
        "Consultation centralisée des événements de sécurité, suivi de leur cycle de vie "
        "et export des données selon le périmètre sélectionné.",
    )

    try:
        response = get_api("/history")

        if response.status_code == 200:
            history = response.json()["history"]

            if history:
                df_history = pd.DataFrame(history)

                for col in ["source", "gravite", "statut", "classe"]:
                    if col not in df_history.columns:
                        df_history[col] = ""

                render_section_heading(
                    "Périmètre de consultation",
                    "Affinez le registre selon le moteur de détection, la sévérité et le statut.",
                )

                col1, col2, col3 = st.columns(3)

                with col1:
                    sources = sorted(
                        item
                        for item in df_history["source"].dropna().astype(str).unique().tolist()
                        if item != ""
                    )
                    filtre_source = st.selectbox(
                        "Moteur de détection",
                        ["Toutes"] + sources,
                        format_func=lambda value: (
                            "Tous les moteurs"
                            if value == "Toutes"
                            else libelle_professionnel(value)
                        ),
                    )

                with col2:
                    gravites = sorted(
                        item
                        for item in df_history["gravite"].dropna().astype(str).unique().tolist()
                        if item != ""
                    )
                    filtre_gravite = st.selectbox(
                        "Niveau de sévérité",
                        ["Toutes"] + gravites,
                        format_func=lambda value: (
                            "Tous les niveaux"
                            if value == "Toutes"
                            else libelle_professionnel(value)
                        ),
                    )

                with col3:
                    statuts = sorted(
                        item
                        for item in df_history["statut"].dropna().astype(str).unique().tolist()
                        if item != ""
                    )
                    filtre_statut = st.selectbox(
                        "Statut de traitement",
                        ["Tous"] + statuts,
                        format_func=lambda value: (
                            "Tous les statuts"
                            if value == "Tous"
                            else libelle_professionnel(value)
                        ),
                    )

                df_filtre = df_history.copy()

                if filtre_source != "Toutes":
                    df_filtre = df_filtre[df_filtre["source"] == filtre_source]

                if filtre_gravite != "Toutes":
                    df_filtre = df_filtre[df_filtre["gravite"] == filtre_gravite]

                if filtre_statut != "Tous":
                    df_filtre = df_filtre[df_filtre["statut"] == filtre_statut]

                colonnes_internes = [
                    "user_id",
                    "historique_id",
                    "historique_type",
                    "historique_index",
                    "event_id",
                ]
                colonnes_affichage = [
                    col for col in df_filtre.columns
                    if col not in colonnes_internes
                ]

                render_section_heading(
                    "Événements correspondant au périmètre",
                    "Le tableau conserve uniquement les données utiles à l'analyse opérationnelle.",
                )
                st.dataframe(
                    styliser_tableau_soc(dataframe_professionnel(df_filtre[colonnes_affichage])),
                    use_container_width=True,
                    hide_index=True,
                )
                st.metric("Événements affichés", len(df_filtre))

                dataframe_export = dataframe_professionnel(
                    df_filtre[colonnes_affichage]
                )
                csv_export = dataframe_export.to_csv(index=False).encode("utf-8-sig")

                filtres_pdf = {
                    "source": (
                        "Tous les moteurs"
                        if filtre_source == "Toutes"
                        else str(libelle_professionnel(filtre_source))
                    ),
                    "gravite": (
                        "Tous les niveaux"
                        if filtre_gravite == "Toutes"
                        else str(libelle_professionnel(filtre_gravite))
                    ),
                    "statut": (
                        "Tous les statuts"
                        if filtre_statut == "Tous"
                        else str(libelle_professionnel(filtre_statut))
                    ),
                }

                dataframe_pdf_export = df_filtre[colonnes_affichage].copy(deep=True)
                filtres_pdf_export = dict(filtres_pdf)

                pdf_export = b""
                erreur_pdf = ""
                try:
                    with st.spinner("Préparation du registre PDF…"):
                        try:
                            pdf_export = preparer_pdf_registre_filtre(
                                dataframe_pdf_export,
                                filtres_pdf_export,
                            )
                        except Exception as erreur_cache:  # noqa: BLE001
                            # Le cache Streamlit ne doit jamais empêcher un export
                            # que ReportLab sait générer directement.
                            print(
                                "[PDF] Repli sans cache après "
                                f"{erreur_cache.__class__.__name__}: {erreur_cache}",
                                flush=True,
                            )
                            pdf_export = generer_pdf_registre_filtre(
                                dataframe_pdf_export,
                                filtres_pdf_export,
                            )

                        if not pdf_export.startswith(b"%PDF-"):
                            raise RuntimeError("Signature PDF absente")
                except Exception as erreur_generation_pdf:  # noqa: BLE001
                    print(
                        "[PDF] Échec de génération : "
                        f"{erreur_generation_pdf.__class__.__name__}: "
                        f"{erreur_generation_pdf}",
                        flush=True,
                    )
                    erreur_pdf = (
                        "Le moteur d'export PDF n'est pas disponible dans le "
                        "conteneur actif. Relancez demarrer.bat avec les nouveaux "
                        "fichiers Docker."
                    )

                export_col1, export_col2 = st.columns(2)
                with export_col1:
                    st.download_button(
                        label="Exporter au format CSV",
                        data=csv_export,
                        file_name="registre_incidents_filtre.csv",
                        mime="text/csv",
                        use_container_width=True,
                    )

                with export_col2:
                    if pdf_export:
                        st.download_button(
                            label="Exporter au format PDF",
                            data=pdf_export,
                            file_name=(
                                "registre_incidents_filtre_"
                                f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
                            ),
                            mime="application/pdf",
                            on_click="ignore",
                            use_container_width=True,
                        )
                    else:
                        st.button(
                            "Exporter au format PDF",
                            disabled=True,
                            use_container_width=True,
                        )

                if erreur_pdf:
                    st.error(erreur_pdf)

                render_section_heading(
                    "Synthèse opérationnelle",
                    "Lecture rapide des tendances observées dans le périmètre actif.",
                )

                total_filtre = len(df_filtre)
                total_non_traitees = int((df_filtre["statut"] == "Non traitee").sum())
                total_traitees = int((df_filtre["statut"] == "Traitee").sum())

                if total_filtre > 0:
                    source_principale = df_filtre["source"].replace("", "Non défini").value_counts().idxmax()
                    gravite_principale = df_filtre["gravite"].replace("", "Non défini").value_counts().idxmax()
                    classe_principale = df_filtre["classe"].replace("", "Non défini").value_counts().idxmax()

                    st.write(
                        f"Le périmètre sélectionné contient **{total_filtre} événement(s)**. "
                        f"Le moteur le plus représenté est **{libelle_professionnel(source_principale)}**, "
                        f"le niveau de sévérité dominant est "
                        f"**{libelle_professionnel(gravite_principale)}** et la menace la plus "
                        f"fréquente est **{classe_principale}**."
                    )

                    col_resume1, col_resume2 = st.columns(2)
                    with col_resume1:
                        st.metric("Incidents traités", total_traitees)
                    with col_resume2:
                        st.metric("Incidents à traiter", total_non_traitees)
                else:
                    st.info("Aucun événement ne correspond au périmètre sélectionné.")

                render_section_heading(
                    "Clôture d'un incident",
                    "Sélectionnez un événement en attente après avoir réalisé les actions de réponse requises.",
                )

                df_non_traitees = df_filtre[df_filtre["statut"] != "Traitee"].copy()

                if df_non_traitees.empty:
                    st.success("Tous les incidents affichés sont clôturés.")
                else:
                    def afficher_alerte(historique_id: str) -> str:
                        ligne = df_non_traitees[
                            df_non_traitees["historique_id"] == historique_id
                        ].iloc[0]

                        source = str(ligne.get("source", ""))
                        gravite = str(ligne.get("gravite", ""))
                        classe = str(ligne.get("classe", ""))
                        date = str(ligne.get("date", ""))

                        return (
                            f"{libelle_professionnel(source)} | "
                            f"{libelle_professionnel(gravite)} | {classe} | {date}"
                        )

                    alerte_selectionnee = st.selectbox(
                        "Incident à clôturer",
                        df_non_traitees["historique_id"].tolist(),
                        format_func=afficher_alerte,
                    )

                    if st.button("Confirmer la clôture", type="primary"):
                        update_response = post_status(alerte_selectionnee, "Traitee")

                        if update_response.status_code == 200:
                            st.success("L'incident a été clôturé dans le registre.")
                            st.rerun()
                        else:
                            afficher_erreur_api(update_response)

            else:
                st.info("Le registre ne contient encore aucun événement de sécurité.")
        else:
            afficher_erreur_api(response)

    except Exception as exc:  # noqa: BLE001
        st.error("Le service de consultation du registre est actuellement indisponible.")
        with st.expander("Consulter les détails techniques"):
            st.code(str(exc))
