all:prepare
prepare:NTSTATUS-Values.xml HRESULT-Values.xml
NTSTATUS-Values.xml:NTSTATUS-Values.html
HRESULT-Values.xml:HRESULT-Values.html
%.xml:%.html
	sed -n \
		-e 's/&nbsp;/ /g' \
		-e '/^<table /,/<\/table>/p' \
		< $< > $@
touch:
	touch NTSTATUS-Values.html HRESULT-Values.html
