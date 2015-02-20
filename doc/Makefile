docs=	\
	kdbus.xml		\
	kdbus.bus.xml		\
	kdbus.connection.xml	\
	kdbus.endpoint.xml	\
	kdbus.fs.xml		\
	kdbus.item.xml		\
	kdbus.match.xml		\
	kdbus.message.xml	\
	kdbus.name.xml		\
	kdbus.policy.xml	\
	kdbus.pool.xml

manpages=$(docs:.xml=.7)
htmlfiles=$(docs:.xml=.html)

%.7: %.xml
	xmlto man -m stylesheet.xsl -o . $<

%.html: %.xml
	xmlto html-nochunks -m stylesheet.xsl -o . $<

mandocs: $(manpages)

htmldocs: $(htmlfiles)

clean::
	rm -rf *.7 *.html *.proc manpages.*
