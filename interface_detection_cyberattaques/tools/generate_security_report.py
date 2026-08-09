from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "output" / "pdf" / "rapport_validation_securite_v10.pdf"
FONT_REGULAR = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"

NAVY = colors.HexColor("#071426")
CYAN = colors.HexColor("#39E7FF")
VIOLET = colors.HexColor("#8A5CFF")
INK = colors.HexColor("#172033")
MUTED = colors.HexColor("#576174")
PALE = colors.HexColor("#EEF7FA")
GREEN = colors.HexColor("#0B8F68")


def register_fonts() -> None:
    pdfmetrics.registerFont(TTFont("DejaVu", FONT_REGULAR))
    pdfmetrics.registerFont(TTFont("DejaVu-Bold", FONT_BOLD))


def page_decor(canvas, document) -> None:
    width, height = A4
    canvas.saveState()
    canvas.setFillColor(NAVY)
    canvas.rect(0, height - 15 * mm, width, 15 * mm, fill=1, stroke=0)
    canvas.setFillColor(CYAN)
    canvas.rect(0, height - 15.8 * mm, width, 0.8 * mm, fill=1, stroke=0)
    canvas.setFont("DejaVu", 8)
    canvas.setFillColor(MUTED)
    canvas.drawString(18 * mm, 10 * mm, "Projet de Stage - Supervision des cyberattaques")
    canvas.drawRightString(width - 18 * mm, 10 * mm, f"Page {document.page}")
    canvas.restoreState()


def build() -> None:
    register_fonts()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    document = SimpleDocTemplate(
        str(OUTPUT),
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=24 * mm,
        bottomMargin=18 * mm,
        title="Rapport de validation de sécurité - v10",
        author="Sadik DASSAA",
    )

    styles = getSampleStyleSheet()
    title = ParagraphStyle(
        "TitleV10",
        parent=styles["Title"],
        fontName="DejaVu-Bold",
        fontSize=23,
        leading=29,
        alignment=TA_CENTER,
        textColor=NAVY,
        spaceAfter=9 * mm,
    )
    subtitle = ParagraphStyle(
        "SubtitleV10",
        parent=styles["Normal"],
        fontName="DejaVu",
        fontSize=11,
        leading=17,
        alignment=TA_CENTER,
        textColor=MUTED,
    )
    heading = ParagraphStyle(
        "HeadingV10",
        parent=styles["Heading2"],
        fontName="DejaVu-Bold",
        fontSize=14,
        leading=18,
        textColor=NAVY,
        spaceBefore=5 * mm,
        spaceAfter=3 * mm,
    )
    body = ParagraphStyle(
        "BodyV10",
        parent=styles["BodyText"],
        fontName="DejaVu",
        fontSize=9.5,
        leading=14.5,
        textColor=INK,
        spaceAfter=2.5 * mm,
    )
    bullet = ParagraphStyle(
        "BulletV10",
        parent=body,
        leftIndent=5 * mm,
        firstLineIndent=-3.5 * mm,
        bulletIndent=0,
        spaceAfter=1.6 * mm,
    )
    callout = ParagraphStyle(
        "CalloutV10",
        parent=body,
        backColor=PALE,
        borderColor=CYAN,
        borderWidth=0.8,
        borderPadding=8,
        spaceBefore=3 * mm,
        spaceAfter=5 * mm,
    )

    story = [
        Spacer(1, 23 * mm),
        Paragraph("Rapport de validation de sécurité", title),
        Paragraph(
            "Plateforme de détection intelligente et automatisée des cyberattaques - version 10 durcie",
            subtitle,
        ),
        Spacer(1, 13 * mm),
        Table(
            [
                ["Étudiant", "Sadik DASSAA"],
                ["Projet", "Supervision des cyberattaques"],
                ["Périmètre", "Suricata, FastAPI, Streamlit, Docker et authentification"],
                ["Date de validation", "9 août 2026"],
                ["Verdict", "Tests techniques réussis - usage local durci"],
            ],
            colWidths=[43 * mm, 112 * mm],
            style=TableStyle(
                [
                    ("FONTNAME", (0, 0), (-1, -1), "DejaVu"),
                    ("FONTNAME", (0, 0), (0, -1), "DejaVu-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("TEXTCOLOR", (0, 0), (0, -1), NAVY),
                    ("BACKGROUND", (0, 0), (0, -1), PALE),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#C7D7E2")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 7),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            ),
        ),
        Spacer(1, 9 * mm),
        Paragraph(
            "Conclusion exécutive : la v10 corrige les principaux écarts identifiés dans la v9. "
            "Elle ne doit toutefois pas être présentée comme sécurisée à 100 % ni comme prête à "
            "être exposée directement sur Internet.",
            callout,
        ),
        PageBreak(),
        Paragraph("1. Mesures de durcissement réalisées", heading),
    ]

    protections = [
        "CORS restreint au dashboard local, validation de l'hôte et en-têtes HTTP de sécurité.",
        "Premier compte administrateur, puis fermeture automatique de l'inscription publique.",
        "Blocage persistant des tentatives de connexion dans SQLite sur une fenêtre de cinq minutes.",
        "Récupération par code e-mail, changement du mot de passe et révocation des sessions.",
        "Journal d'audit du compte avec conservation limitée à 90 jours.",
        "Historiques et statistiques isolés par utilisateur ; refus des accès croisés.",
        "Destinataire e-mail limité au propriétaire vérifié de l'événement.",
        "Extensions et tailles des imports contrôlées avant traitement en mémoire.",
        "Conteneurs non privilégiés, racine en lecture seule, capacités supprimées et ports locaux.",
        "Variables Gmail limitées à l'API ; le dashboard ne reçoit plus ces secrets.",
    ]
    story.extend(
        Paragraph(f"• {item}", bullet) for item in protections
    )

    story.extend(
        [
            Paragraph("2. Paramètres de sécurité", heading),
            Table(
                [
                    ["Contrôle", "Valeur v10"],
                    ["Session authentifiée", "12 heures"],
                    ["Code e-mail", "6 chiffres, 10 minutes, 5 essais"],
                    ["Renvoi du code", "60 secondes minimum"],
                    ["Connexion", "5 échecs par identifiant/client sur 5 minutes"],
                    ["Import CSV", "200 Mo par défaut, plafond configurable 512 Mo"],
                    ["Import EVE", "64 Mo par défaut, plafond configurable 256 Mo"],
                    ["Exposition réseau", "127.0.0.1 uniquement"],
                ],
                colWidths=[65 * mm, 90 * mm],
                repeatRows=1,
                style=TableStyle(
                    [
                        ("FONTNAME", (0, 0), (-1, -1), "DejaVu"),
                        ("FONTNAME", (0, 0), (-1, 0), "DejaVu-Bold"),
                        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#C7D7E2")),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
                        ("FONTSIZE", (0, 0), (-1, -1), 8.8),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ]
                ),
            ),
            PageBreak(),
            Paragraph("3. Résultats des vérifications", heading),
        ]
    )

    tests = [
        ["Vérification", "Résultat"],
        ["Compilation Python et analyse AST", "Réussi"],
        ["Authentification et inscription initiale", "Réussi"],
        ["CORS, TrustedHost et en-têtes HTTP", "Réussi"],
        ["Refus des extensions et fichiers surdimensionnés", "Réussi"],
        ["Isolation entre deux utilisateurs", "Réussi"],
        ["Refus de clôture d'un incident appartenant à un autre compte", "Réussi"],
        ["Changement et récupération du mot de passe", "Réussi"],
        ["Blocage persistant et journal d'audit", "Réussi"],
        ["Analyse des dépendances avec pip-audit", "Aucune vulnérabilité connue signalée"],
        ["Structure Compose analysée", "Valide"],
    ]
    test_table = Table(tests, colWidths=[105 * mm, 50 * mm], repeatRows=1)
    test_table.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (-1, -1), "DejaVu"),
                ("FONTNAME", (0, 0), (-1, 0), "DejaVu-Bold"),
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("TEXTCOLOR", (1, 1), (1, -1), GREEN),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#C7D7E2")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
                ("FONTSIZE", (0, 0), (-1, -1), 8.6),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.extend(
        [
            test_table,
            Paragraph("4. Migration et conservation", heading),
            Paragraph(
                "La base des comptes, l'historique et les journaux Suricata sont conservés. "
                "Le premier compte existant devient administrateur principal. Les lignes v9 "
                "sans propriétaire lui sont attribuées, puis toutes les nouvelles écritures "
                "reçoivent un identifiant utilisateur.",
                body,
            ),
            Paragraph("5. Limites et recommandations", heading),
            Paragraph(
                "Le verdict concerne l'utilisation locale sur le poste Windows déjà validé. "
                "Pour une exposition publique, ajouter au minimum HTTPS, un reverse proxy, une "
                "gestion centralisée des secrets, des sauvegardes chiffrées, une supervision "
                "externe, des mises à jour planifiées et un test d'intrusion indépendant.",
                body,
            ),
            KeepTogether(
                [
                    Spacer(1, 5 * mm),
                    Paragraph(
                        "Verdict final : plateforme locale durcie et testée. Aucun système ne "
                        "peut être garanti sécurisé à 100 %.",
                        callout,
                    ),
                ]
            ),
        ]
    )

    document.build(story, onFirstPage=page_decor, onLaterPages=page_decor)
    print(OUTPUT)


if __name__ == "__main__":
    build()
