docs=	\
	kdbus.xml		\
	kdbus.bus.xml		\
	kdbus.connection.xml	\
	kdbus.endpoint.xml	\
	kdbus.fs.xml		\
	kdbus.item.xml		\
	kdbus.message.xml	\
	kdbus.names.xml		\
	kdbus.policy.xml	\
	kdbus.pool.xml

manpages=$(docs:.xml=.7)

%.7: %.xml
	xmlto man -m stylesheet.xsl -o . $<

mandoc: $(manpages)

