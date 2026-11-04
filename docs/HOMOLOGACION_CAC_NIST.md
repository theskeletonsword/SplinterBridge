# Homologación de anonimización: CAC (China, PIPL Art. 73) y NIST/FTC (EE. UU.)

SplinterBridge v0.8.0. Revisado 2026-11-04.

Este documento describe una arquitectura de cuatro capas para que un perfil
público siga mostrando **exactamente lo que el usuario ve hoy** (nickname,
nombre público, conteo de seguidores y posts) mientras se acerca, técnicamente,
a la definición de **anonimización** exigida por el PIPL art. 73 (China) y el
NIST SP 800-188 / IR 8053 (EE. UU.).

Es orientación de ingeniería, **no una opinión legal ni certificación de
cumplimiento**. El operador debe evaluar con asesoramiento cualificado sus
entidades, datos, fines, escala y las medidas vigentes en cada jurisdicción.

---

## 1. Problema de fondo: el perfil visible sigue siendo "información personal"

Un perfil con nombre y posts se considera información personal cuando existe
una vía técnica o legal razonable para vincularlo a una persona física
(*Shimingzhi*, pasaporte, IP, tarjeta bancaria, etc.). El `federated_did`
actual de SplinterBridge (`HMAC-SHA256(pepper, internal_user_id)`) es
determinista y reversible por el operador de origen que posee el pepper y el
`user_id` local: es **seudonimización**, no anonimización.

Cortar ese enlace de forma matemáticamente demostrable convierte el perfil de
"información personal desidentificada" en una **identidad seudónima autónoma
anonimizada**, para la cual ni el clúster receptor ni un atacante en tránsito
pueden deducir el documento civil detrás.

---

## 2. Diseño de cuatro capas

### Capa 1 — Identificador: Actor Público Autónomo con anclaje ZK

En lugar de derivar el identificador del ID civil, el usuario genera un par de
llaves efímero específico para la federación (`SK_actor`, `PK_actor`).

```
[ Backend Civil Local ]                              [ Red Federada Remota ]
┌─────────────────────────┐                          ┌─────────────────────────┐
│ ID Civil (Shimingzhi)   │                          │ handle: @perex          │
│ RUT / DNI / Pasaporte   │                          │ display_name: Agustín   │
│ FIDO2 / Secure Enclave  │                          │ followers_count: 14.8K  │
└────────────┬────────────┘                          │ public_key: Ed25519_pub │
             │ ZKP (zk-SNARK)                        └────────────▲────────────┘
             ▼                                                    │
┌─────────────────────────┐  Demuestra sin revelar el ID civil:  │
│ Generador de llaves     │  1. Cuenta civil válida en origen      │
│ efímeras del perfil     │  2. Autorización para usar este handle │
│ (SK_actor, PK_actor)    │  3. Ausencia de sanciones activas      │
└─────────────────────────┘                                      │
                                                                 │
             Merkle commitment (raíz solo)                       │
             civil<->actor retenido bajo custodia local          │
```

- Para el clúster remoto, `@perex` es una entidad verificada y viva, pero **no
  existe función matemática ni tabla relacional** que permita deducir el
  número de documento, teléfono o correo que originó la cuenta.
- La prueba ZK completa se conserva **dentro de la jurisdicción de origen**;
  solo cruza la frontera una referencia (commitment hash).

### Capa 2 — Homologación CAC: *Shimingzhi* sin exportar PII

La CAC exige que nadie sea anónimo frente a la ley ante delitos graves o
riesgos para la seguridad nacional (CSL Art. 24). El diseño cumple eso **sin
exportar PII**:

- La verificación de nombre real (*Shimingzhi*) se realiza y conserva **100% en
  el territorio del backend emisor**.
- Se genera un **commitment criptográfico** del vínculo civil ↔ actor.
- La capacidad de abrir ese commitment se divide en fragmentos Shamir
  $(t, n)$ bajo **custodia local de umbral** (por ejemplo, cumplimiento legal
  interno + custodio de llaves auditado por la autoridad nacional).

> Defensa ante la CAC: *"El usuario que publica en el extranjero cumple con el
> registro de nombre real en territorio chino conforme al Art. 24 de la CSL.
> Para cumplir con el Art. 73 del PIPL y evitar la fuga transfronteriza de
> datos, los datos exportados están anonimizados mediante pruebas
> criptográficas de validez. Ante una orden judicial local motivada, el vínculo
> puede auditarse exclusivamente dentro de las fronteras de la República
> Popular China."*

### Capa 3 — Homologación NIST: anonimización de metadatos (SP 800-188)

El NIST advierte que los atributos visibles pueden ser **cuasi-identificadores
(QIDs)** que permiten reidentificar al usuario al combinarse con fuentes
externas.

#### A. Conteo de seguidores: k-anonimato sin pérdida visual

Un número exacto (`14.892`) es una huella dactilar. El contrato Protobuf
fuerza una generalización a nivel de wire:

```protobuf
message SanitizedPublicProfile {
  string handle = 1;
  string display_name = 2;
  // Valor bucketizado (k-anónimo), no el entero exacto.
  uint64 generalized_followers_count = 10;  // ej. 14800 en vez de 14892
  ...
}
```

La aplicación sigue mostrando el valor formateado (`14.8K`), pero el valor
en la red pertenece a un grupo de equivalencia con $k \ge 50$, anulando
ataques de correlación unívoca.

#### B. Nombres y posts: detección de PII directa (NER simplificado)

El `SemanticReviewGate` local ejecuta un escaneo de entidades nombradas antes
de autorizar la salida:

- Si el post incluye RUT/DNI, pasaporte, teléfono, IP o correo, el gateway
  bloquea la exportación (`DropReasonCode::DropReasonDirectPiiDetected`).
- Si el contenido es una opinión, video o comentario social estándar, viaja
  intacto.

Bajo NIST SP 800-188, el contenido expresivo público sin identificadores
directos se clasifica como **datos de riesgo bajo / desidentificados**, aptos
para publicación abierta.

### Capa 4 — Modelo de verificación de publicaciones (posts)

Cada post lleva una firma de autoría generada por la clave privada del actor:

$$\sigma_{\text{post}} = \text{Sign}_{SK_{\text{actor}}}(\text{content\_hash} \parallel \text{timestamp})$$

El gateway receptor valida la firma contra la `PK_actor` del perfil y la
atestación ZK, y almacena el post en su clúster local asociado al handle.
**No consulta ninguna API ni base de datos del país de origen** para renderizar
el perfil con sus posts.

---

## 3. Comparativa: versión actual vs. modelo homologable

| Elemento | Versión actual (0.6.0) | Modelo homologable CAC / NIST | Impacto visual en la app |
|---|---|---|---|
| Identificador interno | `did:splinter:<region>:<hmac>` (seudónimo reversible por origen) | Clave pública autónoma del Actor + prueba ZK de humanidad | Ninguno (ID de ruteo interno) |
| Nickname / Handle | Texto plano (`@handle`) | Namespace federado validado por firma de origen | Idéntico (`@perex`) |
| Display name | Texto plano | Texto plano + filtro de PII directa | Idéntico |
| Seguidores | Entero exacto crudo (`14892`) | Valor bucketizado k-anónimo (`14800`) | Imperceptible (UI muestra `14.8K`) |
| Posts y contenido | Filtro literal de catálogo | Firma de autoría + filtro semántico PII | Idéntico |
| Vínculo civil | Pepper local + user_id en DB | Commitment Merkle bajo custodia local de umbral | No visible |
| Estatus legal | **Seudonimizado** (sujeto a restricciones PIPL/GDPR) | **Anonimizado con atribución criptográfica condicional** | Cumple Art. 73 PIPL y NIST SP 800-188 |

---

## 4. Qué provee esta versión (0.8.0)

| Bloque | Archivo | Propósito |
|---|---|---|
| Contrato proto extendido | `proto/splinter_bridge.proto` | `generalized_followers_count`, `actor_public_key`, `commitment_hash` (perfil); `content_signature`, `zk_proof_reference` (evento). Campos añadidos al final, sin romper compatibilidad. |
| Commitment Merkle | `crates/splinter-core/src/merkle.rs` | Árbol ligero; solo la raíz cruza la frontera. Apertura civil bajo custodia local. |
| k-anonimato seguidores | `crates/splinter-core/src/differential_privacy.rs` | `generalize_followers_count(count, k)` → bucket. |
| PII directa | `crates/splinter-filter/src/lib.rs` | `scan_direct_pii` (email, teléfono, IPv4, RUT chileno) con `DropReasonDirectPiiDetected`. |
| Identidad y firma | `crates/splinter-core/src/identity.rs` | `project_blind_profile_with_options` deriva follower count generalizado y expone clave/commitment del actor. |

---

## 5. Limitaciones declaradas

- No hay modelo de lenguaje entrenado bundulado; la revisión semántica es
  origin-local, acotada y fail-closed.
- La prueba ZK completa (zk-SNARK / Groth16) de "cuenta civil válida sin
  sanciones" es la **siguiente fase de integración** y no está bundulada en
  esta versión; `zk_proof_reference` es el gancho para ella.
- No hay protección contra replay, seguridad de transporte (mTLS) ni servicio
  de federación completo.
- El código no garantiza anonimato ni cumplimiento legal; no declara puerto
  seguro. Véase AGENTS.md (invariantes), docs/LEGAL_DEPLOYMENT.md y
  docs/ANONYMIZACION.md.

---

## 6. Hoja de ruta para homologación real

1. Cliente genera `(SK_actor, PK_actor)` y los registra en el backend de origen
   vinculados al ID civil (local, bajo custodia de umbral).
2. Origen genera el Merkle commitment y expone solo `commitment_hash`.
3. `SK_actor` firma cada post; el receptor verifica con `PK_actor`.
4. Integrar una librería ZK real (ej. Halo2 / Bellman) para la prueba de
   "personhood válida" y reemplazar `zk_proof_reference` por la verificación de
   la prueba contra una clave de verificación pública.
5. Formalizar el contrato de transferencia ante la CAC (evaluación o contrato
   estándar) y un mecanismo Art. 46 GDPR (SCCs/BCR) con evaluación contextual.
