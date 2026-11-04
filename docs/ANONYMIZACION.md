# Anonimización, seudonimización y SplinterBridge

PIPL art. 73 (China) y GDPR Considerando 26 (UE/EEE). Revisado 2026-11-04.

Este documento es orientación de ingeniería, no una opinión legal ni certificación
de cumplimiento. El operador debe evaluar con asesoramiento cualificado sus
entidades, datos, fines y escala.

## 1. El problema de fondo: el DID derivado por HMAC-SHA256 es seudonimización

El identificador federado actual de SplinterBridge es:

```
did:splinter:<region>:<hex(HMAC-SHA256(pepper, region_code ":" user_id))>
```

Es determinista. El backend de origen conserva en su base de datos local el
`user_id` original y en su HSM/memoria el pepper regional. Si un tribunal o la
policía presenta al nodo chino un `user_id` y le pide que aplique la función y
diga si un DID es de esa persona, la respuesta es inmediata y determinista.

Eso es **seudonimización reversible por el origen**, no anonimización:

- **PIPL art. 73**: la anonimización requiere que la información se procese de
  modo que no se pueda identificar a una persona natural por medio razonable
  alguno, y que el proceso sea técnicamente irreversible, también para el
  originador. Un HMAC con pepper conocido por el origen falla este test.
- **GDPR Considerando 26**: idéntico requisito; si es posible la reidentificación
  por medios razonables, sigue siendo dato personal.

Conclusión: `project_blind_profile` y los DIDs opacos son **pseudonimización de
máxima frontera (state-of-the-art pseudonymization)**. Protegen de la
vigilancia masiva automatizada y evitan que los backends se sincronicen las bases
de identidad civil, pero no eliminan la capacidad del nodo emisor de reidentificar.

## 2. Los tres caminos técnicos viables

### 2.1 K-anonimato + ruido diferencial (métricas, tendencias, telemetría)

Si lo que cruza la frontera no es un perfil individual sino agregados
(interacciones, tendencias de música, vistas):

- **Privacidad diferencial (ε, δ):** inyectar ruido gaussiano o laplaciano a nivel
  de gateway en conteos antes de emitirlos. Nuevo módulo:
  `splinter_core::differential_privacy` (`noisy_count`, `laplace_noise`,
  `gaussian_noise`).
- **K-anonimato / L-diversidad:** el gateway emite solo bloques agregados donde
  cada evento se mezcla indistinguiblemente con al menos k usuarios (k ≥ 100).
  Nuevo módulo: `splinter_core::differential_privacy::k_anonymous_bucket`.

Resultado legal: sin traza individual ni identificador único, deja de ser dato
personal para el PIPL y el GDPR. Pierde utilidad para perfiles, seguidores o
reputación individual.

### 2.2 Identidades efímeras sin estado ni memoria

Si se requiere interacción (comentarios, contenido visible al extranjero) pero la
plataforma renuncia al "perfil persistente unificado":

- Cada interacción o hilo genera un identificador temporal derivado de un secreto
  efímero que rota diariamente o por publicación.
- Tabla de correspondencia destruida en RAM mediante crypto-shredding
  (`zeroize` / `blkdiscard`).
- Prueba de humanidad sin registro: aserción FIDO2/WebAuthn ciega o credenciales
  anónimas (Privacy Pass / BBS+), con verificabilidad criptográfica pero
  imposible vinculación entre firmas (unlinkability).

Nuevo módulo: `splinter_core::ephemeral`
(`derive_ephemeral_did`, `EphemeralSession`, `EphemeralPepper`,
`EphemeralVault`). Los DIDs efímeros tienen formato
`did:splinter:eph:<region>:<digest>`, derivados de una clave de época que se
zeroiza tras la rotación. Dos interacciones de la misma cuenta en épocas
distintas son matemáticamente no vinculables sin la semilla destruida.

Resultado legal: ni el emisor ni el receptor pueden rastrear al autor ni
vincular sus posts; reversibilidad cero.

### 2.3 Cero conocimiento total (ZKP: SNARKs / Groth16)

Validar permisos y atributos sin enviar dato identificador alguno:

- el autor es una cuenta válida registrada hace > 30 días,
- mayoría de edad sin revelar fecha de nacimiento,
- no está en lista de cuentas suspendidas.

El receptor verifica la prueba contra una clave pública. No hay DID, handle, IP
ni metadatos persistentes.

Resultado legal: imposibilidad absoluta de reidentificación. Cumple PIPL art. 73,
pero supone complejidad criptográfica elevada y no existe implementación en este
repositorio.

## 3. El dilema de la red social real

Si el usuario publica video con su cara/voz y asigna un identificador persistente
para que sus seguidores lo reconozcan (@perex, historial de videos y
comentarios), es ontológicamente imposible hablar de anonimización legal
absoluta: siempre existe capacidad de vincular contenido con persona física.

Por eso el diseño actual de SplinterBridge (`MINIMAL_EGRESS_V1`,
`project_blind_profile`, DIDs opacos, backends mutuamente ciegos) no pretende ser
"anonimato fantasma", sino **mínimización de datos y seudonimización de máxima
frontera**.

## 4. Camino realista de la industria (China ↔ Occidente)

Para que el flujo sea legal, no hay que fingir una anonimización que destruiría
la red social. El camino realista es homologar esta seudonimización blindada
dentro de los mecanismos formales de transferencia:

- **China:** evaluación formal de la CAC o depósito de contrato estándar (PIPL
  arts. 55-56, medidas 2024 y FAQ enero 2026), con evaluación de impacto,
  clasificación de datos, ciberseguridad y deberes de contenido. Véase
  docs/LEGAL_DEPLOYMENT.md.
- **UE/EEE:** mecanismo del art. 46 GDPR (SCD o BCR) más evaluación contextual
  tipo EDPB 01/2020; un filtro, seudónimo o firma Ed25519 no es por sí mismo
  instrumento de transferencia ni prueba de cumplimiento de Schrems II.

## 5. Qué provee esta versión (0.7.0)

| Módulo | Propósito | Garantía legal |
|---|---|---|
| `identity::derive_federated_did` | DID pseudónimo estable por región | Seudonimización reversible por el origen; no anonimización |
| `ephemeral::derive_ephemeral_did` | DID efímero por época, semilla zeroizada | No vinculable entre épocas; reversibilidad cero tras shredding |
| `differential_privacy` | Conteo ruidoso y k-anónimo para agregados | Salida sin traza individual (métricas/telemetría) |

Los DIDs efímeros de `ephemeral` son un bloque de construcción independiente en
esta versión: aún no son aceptados por `boundary::validate_event` ni cableados
en `OutboundGateway::prepare_local`. Esa integración (extender `valid_did`)
queda como trabajo del adaptador.

## 6. Limitaciones declaradas

- No hay modelo de lenguaje entrenado bundulado; la revisión semántica es
  origin-local, acotada y fail-closed.
- No hay protección contra replay, validación de hardware, seguridad de
  transporte ni servicio de federación completo.
- El código no garantiza anonimato ni cumplimiento legal; no declara puerto
  seguro. Véase AGENTS.md (invariantes) y docs/LEGAL_DEPLOYMENT.md.
