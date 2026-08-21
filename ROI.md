# Retour sur Investissement (ROI)

## Définition

Le ROI (*Return on Investment*) mesure le rendement d'un investissement par rapport à son coût :

```
ROI = (Gain - Investissement) / Investissement × 100
```

## Scénario de référence — Vente unique

En reprenant les coûts estimés du projet :

| Poste | Montant |
|---|---:|
| Investissement total (R&D + Développement + Infrastructure 1 an) | 38 200 € |
| Prix de vente estimé | 42 000 € |
| **Marge brute** | **3 800 €** |
| **ROI** | **9,95 %** |

> Le projet est rentable dès la première vente. Le ROI reste modeste car le prix intègre déjà une marge commerciale faible (~10 %) adaptée à un contexte académique / premier client.

## Scénario commercial — Licences récurrentes

Si Cipherfall est commercialisé sous forme de licences annuelles (SaaS ou on-premise) avec un support actif :

| Hypothèse | Valeur |
|---|---:|
| Licence annuelle par client | 12 000 € |
| Coût support + infrastructure / client / an | 1 500 € |
| Marge annuelle par client | 10 500 € |
| Nombre de clients année 1 | 5 |
| **Marge annuelle totale** | **52 500 €** |
| **ROI année 1** | **37,4 %** |
| **Seuil de rentabilité** | **8,7 mois** |

À partir de l'année 2, l'investissement initial étant amorti, le ROI devient très élevé (≈ 137 % par an sur la base des mêmes 5 clients, sans nouveau développement majeur).

## Scénario défensif — Réduction du risque

Dans un contexte SOC/Blue Team, le retour ne se mesure pas en ventes mais en risque évité. Le coût moyen d'une compromission APT est estimé à plusieurs millions d'euros (IBM : 4,45 M$ en 2023). Si l'utilisation de Cipherfall pour entraîner les équipes et valider les détections permet d'éviter un incident majeur tous les 10 ans :

| Poste | Montant |
|---|---:|
| Investissement | 38 200 € |
| Valeur actualisée du risque évité (1 incident / 10 ans) | ~445 000 € |
| **ROI** | **+1 065 %** |

> Ce scénario illustre la valeur défensive : un faible investissement en simulation offensive peut générer un retour disproportionné en cas d'évitement d'une compromission réelle.

## Synthèse comparative

| Scénario | Investissement | Gain année 1 | ROI | Seuil de rentabilité |
|---|---|---:|---:|---:|
| Vente unique | 38 200 € | 42 000 € | 9,95 % | Immédiat |
| Licences 5 clients | 38 200 € | 52 500 € | 37,4 % | 8,7 mois |
| Réduction du risque APT | 38 200 € | ~445 000 €* | +1 065 % | Immédiat |

\* Valeur actualisée sur 10 ans d'un incident majeur évité.

## Conclusion

Le projet Cipherfall présente un **ROI positif dès la première vente** dans sa forme actuelle. Sa rentabilité croît fortement sous un modèle de licences récurrentes. Sa valeur défensive — capacité à former les équipes et à valider les détections avant qu'une menace réelle ne frappe — représente le scénario de retour le plus impactant, bien que non monétisable directement.
