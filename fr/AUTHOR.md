# Un mot de l'auteur

Ce document est le fruit de **nombreuses** heures de réflexion approfondie, de recherches et d'allers-retours dans la prise de décision. **Chaque** paramètre, **chaque** choix d'algorithme, **chaque** octet dans les formats de blob a été pesé face à des contraintes du **monde réel**.

Ce qui protège les utilisateurs contre les menaces **réalistes**, ce qui reste utilisable pour des personnes ordinaires, ce qui peut être audité par des chercheurs en sécurité, et ce qui aura encore du sens **dans cinq ans**.

## Nos valeurs

**VexaHub** repose sur une **conviction fondamentale**. Nous croyons que la **vie privée** ne devrait pas être une fonctionnalité premium, et que **« faites-nous confiance »** n'est pas un modèle de sécurité. Le seul chiffrement qui mérite d'être appelé **bout en bout** est celui où les personnes qui gèrent les serveurs ne peuvent réellement **pas** lire vos fichiers, non pas parce qu'elles le promettent, mais parce que les mathématiques ne le **permettent** pas.

> Tout dans cette spécification découle de cette conviction.
>
> - **OPAQUE** signifie que le serveur ne voit jamais les mots de passe.
>
> - **Argon2id** à 128 Mio rend les attaques hors-ligne computationnellement prohibitives.
>
> - **XChaCha20-Poly1305** élimine les risques de réutilisation de nonce.
>
> - **X-Wing** garantit que le partage survit à l'avènement des ordinateurs quantiques.
>
> Une seule crate Rust comme **source de vérité cryptographique** signifie que chaque client VexaHub (web, bureau, mobile) parle exactement le même langage jusqu'au dernier octet.

## Notes

Rien de tout cela n'est parfait. La cryptographie ne l'est **jamais**. Mais c'est **honnête**, c'est **documenté**, et c'est **ouvert** à l'examen.

Si vous trouvez une erreur dans ce document, **contactez-nous** ! La sécurité est un effort **collaboratif**, et **VexaHub** est meilleur avec votre aide que **sans**.

À toute personne qui lit ceci et qui construit quelque chose de similaire. Ne **lésinez pas** sur la crypto. Vos utilisateurs vous confient ce qu'ils possèdent de plus personnel. Prenez cette confiance **au sérieux**.

Conçu avec soin en **France** ![Magnifique drapeau français](/public/fr.svg) - Pour tous ceux qui croient que la vie privée est un **droit**, et non un **privilège**.

Avec amour de la part de l'équipe ❤
