# Architecture Diagrams

Architecture diagrams are maintained as code.

## Tools

| Tool | Purpose | Command | Output |
| --- | --- | --- | --- |
| PlantUML | Validate runtime sequence diagrams | `plantuml --check-syntax diagrams/plantuml/sequence/*.puml` | Validation on stdout |
| PlantUML | Render SVG artifacts | `plantuml --format svg --output-dir "$PWD/diagrams/artefacts/plantuml" diagrams/plantuml/sequence/*.puml` | `diagrams/artefacts/plantuml/*.svg` |

Generated SVG files are ignored review artifacts; the `.puml` files are the source of truth.
