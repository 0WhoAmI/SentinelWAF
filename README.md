# 🛡️ Sentinel WAF

> **Projekt badawczy realizowany w ramach pracy magisterskiej:** 
> *"Analiza porównawcza skuteczności i wydajności metod sygnaturowych oraz uczenia maszynowego w detekcji ataków webowych."*

---

## 📋 O Projekcie

**Sentinel WAF** to hybrydowy system zabezpieczeń aplikacji webowych (Web Application Firewall) napisany w **.NET 10**.

Celem projektu jest analiza i porównanie dwóch podejść do detekcji zagrożeń webowych:

- **deterministycznego** (reguły sygnaturowe oparte o wyrażenia regularne),
- **probabilistycznego** (uczenie maszynowe z wykorzystaniem ML.NET).

System działa jako **ASP.NET Core Middleware**, analizując przychodzące żądania HTTP pod kątem zagrożeń takich jak:
- SQL Injection,
- Cross-Site Scripting (XSS),
- Command Injection.

---

### 🎯 Cele Badawcze
1. **Skuteczność detekcji (Detection Rate)**  
   Porównanie zdolności obu podejść do wykrywania ataków klasycznych, obfuskowanych oraz zmodyfikowanych.

2. **Wydajność (Performance)**  
   Analiza narzutu czasowego (latency) oraz zużycia zasobów (CPU / RAM) generowanego przez każdy silnik.

3. **False Positives / False Negatives**  
   Ocena podatności silników na błędną klasyfikację legalnych żądań jako ataków.
   
---

## 🏗️ Architektura

Projekt został zrealizowany w oparciu o **Clean Architecture (Robert C. Martin)** z wyraźnym rozdzieleniem:

- logiki domenowej,
- przypadków użycia (Use Cases),
- infrastruktury,
- integracji z ASP.NET.

Architektura została zaprojektowana tak, aby:
- umożliwiać łatwą wymianę silników detekcji,
- zapewnić wysoką testowalność,
- być gotową do dystrybucji jako pakiet **NuGet**.

---

## 📂️ Struktura rozwiązania

- **`src`** – główne projekty biblioteczne
  - `'SentinelWaf.Domain'` – definicje modeli, value objects, enumów i wyników detekcji. Czysta logika domenowa, bez zależności od frameworków.  
  - `'SentinelWaf.Application'` – serce systemu. Zawiera:
    - `'Abstractions'` – kontrakty (`IRequestAnalysisService`, `IDetectionPipeline`, `IThreatDetectionEngine`)  
    - `'UseCases'` – implementacja przypadków użycia (`RequestAnalysisService`)  
    - `'Pipelines'` – orkiestracja silników detekcji (`DetectionPipeline`)  
  - `'SentinelWaf.Infrastructure'` – implementacja silników detekcji i szczegóły techniczne:
    - `'DetectionEngines/RegexEngine'` – silnik sygnaturowy z regułami i opcjami czułości  
    - `'Telemetry'` – zbieranie metryk i czasu wykonania  
    - `'Options'` – konfiguracje np. `SignatureDetectionOptions`  
  - `'SentinelWaf.Middleware'` – integracja z ASP.NET Core. Przechwytuje requesty, wywołuje Use Case, podejmuje decyzję o blokowaniu lub przepuszczeniu żądania.

- **`playground`** – środowisko testowe / aplikacja „ofiara”
  - `'VulnerableWebApp'` – Web API podatne na ataki, używane do testowania skuteczności WAF-a.

- **`tests`** – projekt testowy
  - `'SentinelWaf.Tests'` – testy jednostkowe dla domeny, silnika Regex, pipeline i przypadków użycia. Weryfikują zarówno pozytywne, jak i negatywne przypadki oraz poziomy czułości.

---

### 🧠 Przepływ analizy żądania

1. Żądanie HTTP trafia do aplikacji („ofiary”).
2. `SentinelWafMiddleware` przechwytuje request.
3. Middleware wywołuje **Use Case**: `RequestAnalysisService`.
4. Use Case deleguje analizę do `DetectionPipeline`.
5. Pipeline uruchamia skonfigurowane silniki detekcji (np. Regex).
6. Wynik analizy (`ThreatDetectionResult`) wraca do middleware.
7. Middleware:
   - blokuje żądanie (403),
   - lub przekazuje je dalej w potoku.

---

## 🚀 Technologie

Projekt wykorzystuje najnowszy stos technologiczny Microsoft:
* **.NET 10**
* **ASP.NET Core Middleware**
* **ML.NET** (Binary Classification)
* **xUnit** (Testy)
* **Docker** (Planowane wdrożenie konteneryzacji)

---

## 📅 Roadmapa (Plan Realizacji)

- [x] **Faza 1:**  
  Inicjalizacja struktury projektu, architektura Clean Architecture, definicja kontraktów i modeli domenowych.

- [x] **Faza 2:**  
  Implementacja deterministycznego silnika sygnaturowego (Regex) z obsługą poziomów czułości oraz testami.

- [ ] **Faza 3:**  
  Integracja Middleware oraz uruchomienie środowiska testowego (Playground – aplikacja ofiara).

- [ ] **Faza 4:**  
  Implementacja silnika AI (ML.NET) – trening modelu i adapter zgodny z pipeline.

- [ ] **Faza 5:**  
  Benchmarking – porównanie wydajności i skuteczności (Regex vs AI).

- [ ] **Faza 6:**  
  Konteneryzacja (Docker), publikacja pakietu NuGet oraz finalizacja pracy magisterskiej.