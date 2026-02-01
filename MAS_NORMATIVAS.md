# MAS_NORMATIVAS.md - Analisis de Referencia para Clientes Sectoriales

> **Proyecto:** PDFSigner v2.0
> **Fecha:** 2026-02-01
> **Tipo:** Documento de referencia (NO roadmap obligatorio)
> **Normativas:** PCI-DSS v4.0 | CMMC 2.0 Level 2 | DORA | NIS2

---

## IMPORTANTE: Aplicabilidad

```
┌─────────────────────────────────────────────────────────────────────┐
│                    ⚠️  AVISO DE APLICABILIDAD                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  PDFSigner es una aplicacion de FIRMA DIGITAL de PDFs.              │
│                                                                     │
│  Las normativas en este documento NO son obligatorias para el       │
│  funcionamiento normal de la aplicacion. Solo aplican si:           │
│                                                                     │
│  • PCI-DSS  → Un cliente requiere firmar docs con datos de pago     │
│  • CMMC     → Se licita un contrato con el DoD de USA               │
│  • DORA     → Un banco/aseguradora EU lo exige contractualmente     │
│  • NIS2     → Un operador de infra critica EU lo requiere           │
│                                                                     │
│  NORMATIVAS YA IMPLEMENTADAS (100%):                                │
│  ✅ eIDAS - Firmas electronicas cualificadas EU                     │
│  ✅ HIPAA - Documentos medicos USA                                  │
│  ✅ GDPR  - Proteccion de datos EU                                  │
│  ✅ NIST 800-53 - 26 controles de seguridad                         │
│  ✅ SOC 2 - CC1-CC4 controles                                       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Resumen de Compliance Actual

### Lo que YA tenemos (Suficiente para 95% del mercado)

| Normativa | Sector | Estado | Notas |
|-----------|--------|--------|-------|
| **eIDAS** | Firmas EU | ✅ 100% | PAdES B-LTA, TSP Registry, QES validation |
| **HIPAA** | Healthcare USA | ✅ 100% | Encryption, audit, access control |
| **GDPR** | Privacidad EU | ✅ 100% | Consent, breach notification, data export |
| **NIST 800-53** | Gobierno USA | ✅ 85% | 26 controles automatizados |
| **SOC 2** | SaaS/Cloud | ✅ 80% | CC1-CC4 implementados |
| **FIPS 140-2** | Criptografia | ✅ 100% | Algoritmos certificados |

### Lo que este documento cubre (Solo si un cliente lo requiere)

| Normativa | Sector | Cuando aplica | Probabilidad |
|-----------|--------|---------------|--------------|
| **PCI-DSS v4.0** | Pagos | Si los PDFs contienen datos de tarjetas | BAJA |
| **CMMC 2.0 L2** | Defensa USA | Si se vende al DoD con CUI | BAJA |
| **DORA** | Finanzas EU | Si un banco/aseguradora lo exige | MEDIA |
| **NIS2** | Infra critica EU | Si una utility/telco lo exige | MEDIA |

---

## PARTE 1: PCI-DSS v4.0 (Pagos/Finanzas)

### Aplicabilidad: BAJA

> **Cuando aplica:** Solo si PDFSigner procesa, almacena o transmite datos de tarjetas de pago (PAN, CVV, etc.) dentro de los PDFs firmados.
>
> **Recomendacion:** NO procesar datos de tarjetas. Si un cliente lo requiere, usar tokenizacion con payment gateway certificado.

### Estado Actual: 35% (si aplicara)

| Categoria | Cumple | Parcial | Gap |
|-----------|--------|---------|-----|
| Network Security (Req 1-2) | 1 | 1 | 2 |
| Data Protection (Req 3-4) | 1 | 0 | 1 |
| Vulnerability Mgmt (Req 5-6) | 0 | 2 | 1 |
| Access Control (Req 7-9) | 2 | 0 | 1 |
| Monitoring (Req 10-11) | 1 | 1 | 1 |
| Policy (Req 12) | 0 | 1 | 1 |

### Gaps Principales (Solo si aplica)

| Gap | Severidad | Esfuerzo | Costo Externo |
|-----|-----------|----------|---------------|
| HSM para key management | CRITICA | 24h | Pay-per-use |
| WAF deployment | CRITICA | 8h | $200-500/mes |
| PAN truncation/masking | CRITICA | 12h | $0 |
| Pentest anual | CRITICA | External | $15-30k |
| ASV scanning trimestral | ALTA | External | $5k/ano |
| ClamAV para PDFs | ALTA | 12h | $0 |
| IDS/IPS | ALTA | 16h | $0-300/mes |
| QSA Certification | OBLIGATORIA | External | $30-50k |

**Inversion total si aplica:** 245h desarrollo + $50-86k/ano externos

---

## PARTE 2: CMMC 2.0 Level 2 (Defensa USA - DoD)

### Aplicabilidad: BAJA

> **Cuando aplica:** Solo si PDFSigner se vende al Departamento de Defensa de USA o a contractors que manejan CUI (Controlled Unclassified Information).
>
> **Recomendacion:** Mantener NIST 800-53 base. Solo invertir en CMMC si hay un contrato DoD especifico.

### Estado Actual: 70% (si aplicara)

| Dominio | Estado | Notas |
|---------|--------|-------|
| AC (Access Control) | ✅ Cumple | RBAC, MFA, sessions |
| AU (Audit) | ✅ Cumple | HMAC chain, SIEM |
| IA (Authentication) | ✅ Cumple | MFA, Argon2, policy |
| SC (System Protection) | ✅ Cumple | FIPS, TLS, encryption |
| CM (Config Mgmt) | ⚠️ Parcial | Falta CMP formal |
| IR (Incident Response) | ⚠️ Parcial | IRP existe, falta tracking |
| RA (Risk Assessment) | ⚠️ Parcial | VulnTracker existe |
| CA (Security Assessment) | ⚠️ Parcial | Tests existen, falta SSP |
| SI (System Integrity) | ⚠️ Parcial | Scanning existe, falta FIM |
| MP (Media Protection) | ❌ Gap | Sin policy formal |
| MA (Maintenance) | ❌ Gap | Sin policy formal |
| PS (Personnel Security) | ❌ Gap | Sin background checks |

### Gaps Principales (Solo si aplica)

| Gap | Tipo | Esfuerzo |
|-----|------|----------|
| System Security Plan (SSP) | Documentacion | 40h |
| Plan of Action & Milestones (POA&M) | Documentacion | 20h |
| Configuration Management Plan | Documentacion | 30h |
| Personnel Security Policy | Documentacion | 25h |
| Media Protection Policy | Documentacion | 15h |
| C3PAO Assessment | Certificacion | $20-50k |

**Inversion total si aplica:** 300-450h desarrollo + $35-80k certificacion

---

## PARTE 3: DORA (Finanzas UE)

### Aplicabilidad: MEDIA

> **Cuando aplica:** Si un banco, aseguradora, fondo de inversion u otra entidad financiera regulada en la UE contrata PDFSigner como proveedor ICT y lo incluye en su registro de terceros criticos.
>
> **Recomendacion:** Preparar documentacion basica. Solo implementar codigo si hay contrato firmado.

### Estado Actual: 48% (si aplicara)

| Pilar DORA | Cumplimiento | Estado |
|------------|--------------|--------|
| 1. ICT Risk Management | 70% | Parcial |
| 2. Incident Management | 65% | Parcial |
| 3. Resilience Testing | 40% | Debil |
| 4. Third-Party Risk | 15% | Muy Debil |
| 5. Information Sharing | 10% | Muy Debil |

### Gaps Principales (Solo si aplica)

| Gap | Severidad | Tipo | Esfuerzo |
|-----|-----------|------|----------|
| NCA Reporter (notificacion 72h) | CRITICA | Codigo | 60h |
| Third-Party Risk Register | CRITICA | Codigo | 50h |
| Major Incident Classification | ALTA | Codigo | 20h |
| Vendor Due Diligence Process | ALTA | Proceso | 30h |
| Resilience Testing Framework | ALTA | Codigo | 50h |
| Exit Strategies Documentation | MEDIA | Docs | 30h |
| TLPT (Threat-Led Pentest) | MEDIA | Externo | EUR50-150k |

**Inversion total si aplica:** 200-280h desarrollo + EUR50-150k externos

---

## PARTE 4: NIS2 (Infraestructura Critica UE)

### Aplicabilidad: MEDIA

> **Cuando aplica:** Si un operador de infraestructura critica (energia, agua, transporte, salud, telecoms) en la UE contrata PDFSigner y lo considera parte de su cadena de suministro critica.
>
> **Recomendacion:** La base ya existe (68% compliance). Solo faltan items organizacionales.

### Estado Actual: 68% (si aplicara)

| Requisito Art. 21 | Estado | Cobertura |
|-------------------|--------|-----------|
| (a) Risk analysis | ✅ | 95% |
| (b) Incident handling | ⚠️ | 70% (falta CSIRT) |
| (c) Business continuity | ⚠️ | 50% (falta BCP) |
| (d) Supply chain | ⚠️ | 45% |
| (e) SDLC security | ⚠️ | 75% |
| (f) Effectiveness assessment | ⚠️ | 60% |
| (g) Cryptography | ✅ | 100% |
| (h) Access control | ✅ | 95% |
| (i) MFA | ✅ | 100% |
| (j) Secure communications | ✅ | 100% |
| (k) Training | ⚠️ | 40% |

### Gaps Principales (Solo si aplica)

| Gap | Severidad | Tipo | Esfuerzo |
|-----|-----------|------|----------|
| CSIRT Notification (24h/72h) | CRITICA | Codigo | 30h |
| Business Continuity Plan | ALTA | Docs | 35h |
| NIS2 Governance Framework | ALTA | Docs | 20h |
| Supply Chain Security Policy | MEDIA | Docs | 25h |
| Security Awareness Program | MEDIA | Docs | 20h |
| Risk Register formal | MEDIA | Docs | 20h |

**Inversion total si aplica:** 150-195h desarrollo + EUR10-20k auditoria

---

## RESUMEN: Que Implementar y Cuando

### Nivel 0: Ya Implementado (No hacer nada)

```
✅ eIDAS, HIPAA, GDPR, NIST 800-53, SOC 2, FIPS 140-2
   → Suficiente para 95% del mercado de firma digital
```

### Nivel 1: Buenas Practicas (Recomendado independientemente)

| Item | Esfuerzo | Beneficio |
|------|----------|-----------|
| Penetration Testing anual | $15-30k | Encuentra vulnerabilidades reales |
| Business Continuity Plan | 35h docs | Preparacion ante desastres |
| Load Testing basico | 20h | Conocer limites del sistema |

**Total Nivel 1:** 55h + $15-30k

### Nivel 2: Si un cliente DORA/NIS2 lo requiere

| Item | Esfuerzo | Trigger |
|------|----------|---------|
| CSIRT/NCA Notification | 90h codigo | Contrato con banco/utility EU |
| Third-Party Risk Register | 50h codigo | Requisito contractual DORA |
| Documentacion governance | 100h docs | Auditoria del cliente |

**Total Nivel 2:** 240h (solo si hay contrato)

### Nivel 3: Si un cliente DoD/CMMC lo requiere

| Item | Esfuerzo | Trigger |
|------|----------|---------|
| SSP + POA&M + CMP | 90h docs | Licitacion DoD |
| Policies (PS, MP, MA) | 55h docs | Requisito CMMC L2 |
| C3PAO Assessment | $20-50k | Certificacion obligatoria |

**Total Nivel 3:** 145h + $20-50k (solo si hay licitacion)

### Nivel 4: Si se procesan pagos (NO recomendado)

| Item | Esfuerzo | Trigger |
|------|----------|---------|
| PCI-DSS completo | 245h | Cliente exige procesar CHD |
| HSM + WAF + IDS | Infra | Requisito tecnico |
| QSA Certification | $30-50k | Obligatorio para compliance |

**Total Nivel 4:** 245h + $50-86k/ano (evitar si es posible)

---

## Decision Tree

```
                    ¿Que tipo de cliente?
                           │
           ┌───────────────┼───────────────┐
           │               │               │
      Empresas         Gobierno        Financiero
      Generales          USA              EU
           │               │               │
           ▼               ▼               ▼
    ┌──────────┐    ┌──────────┐    ┌──────────┐
    │ NIVEL 0  │    │ ¿DoD?    │    │ ¿Banco/  │
    │ (actual) │    │          │    │ Utility? │
    │ ✅ LISTO │    └────┬─────┘    └────┬─────┘
    └──────────┘         │               │
                    ┌────┴────┐     ┌────┴────┐
                    │ SI: L3  │     │ SI: L2  │
                    │ CMMC    │     │DORA/NIS2│
                    └─────────┘     └─────────┘
                    │ NO: L0  │     │ NO: L0  │
                    │ (actual)│     │ (actual)│
                    └─────────┘     └─────────┘
```

---

## Costos por Escenario

| Escenario | Desarrollo | Externos/Ano | Total Ano 1 |
|-----------|------------|--------------|-------------|
| **Actual (sin cambios)** | 0h | $0 | $0 |
| **+ Buenas practicas (L1)** | 55h | $15-30k | $20-35k |
| **+ Cliente EU (L2)** | 240h | $25-50k | $50-75k |
| **+ Cliente DoD (L3)** | 145h | $35-80k | $50-95k |
| **+ Pagos (L4)** | 245h | $50-86k | $75-110k |
| **TODO (no recomendado)** | 768h | $150-350k | $225-425k |

---

## Archivos de Referencia (Crear solo si se necesita)

### Si cliente DORA/NIS2:
```
src/pdfsigner/core/compliance/dora/
    nca_reporter.py           # Solo si contrato EU
    third_party_risk.py       # Solo si contrato EU

docs/security/
    business-continuity-plan.md
    supply-chain-security.md
```

### Si cliente CMMC:
```
docs/compliance/
    SSP.md                    # Solo si licitacion DoD
    POAM.md
    CMP.md
```

### Si cliente PCI-DSS (evitar):
```
src/pdfsigner/core/pci/
    pan_handler.py            # Solo si procesa pagos
    hsm_integration.py
```

---

## Conclusion

**PDFSigner ya esta preparado para el mercado de firma digital** con eIDAS, HIPAA, GDPR y NIST implementados.

Las normativas en este documento son **referencias para casos especificos**:

| Normativa | Accion Recomendada |
|-----------|-------------------|
| PCI-DSS | ❌ No implementar (no aplica) |
| CMMC | 📋 Guardar como referencia |
| DORA | 📋 Preparar docs si hay interes de bancos EU |
| NIS2 | 📋 Preparar docs si hay interes de utilities EU |

**Inversion recomendada ahora:** Solo Nivel 1 (55h + pentest) = ~$25-35k

---

*Documento de referencia - No es roadmap obligatorio*
*Ultima actualizacion: 2026-02-01*
*Revisar cuando haya cliente sectorial especifico*
