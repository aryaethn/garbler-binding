main.pdf: main.tex refs.bib
	pdflatex -interaction=nonstopmode main.tex >/dev/null
	bibtex main >/dev/null || true
	pdflatex -interaction=nonstopmode main.tex >/dev/null
	pdflatex -interaction=nonstopmode main.tex | tail -3

clean:
	rm -f main.aux main.bbl main.blg main.log main.out main.pdf

.PHONY: clean
