.PHONY: pdf

pdf:
	DYLD_LIBRARY_PATH=/opt/homebrew/lib pandoc docs/RESEARCH_REPORT.md \
		--pdf-engine=weasyprint \
		--css=docs/report.css \
		--metadata title="PromptSentry Research Report" \
		-o docs/RESEARCH_REPORT.pdf
	@echo "Generated docs/RESEARCH_REPORT.pdf"
