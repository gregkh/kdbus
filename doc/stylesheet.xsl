<?xml version="1.0" encoding="UTF-8"?>
<stylesheet xmlns="http://www.w3.org/1999/XSL/Transform" version="1.0">
	<param name="chunk.quietly">1</param>
	<param name="funcsynopsis.style">ansi</param>
	<param name="funcsynopsis.tabular.threshold">80</param>
	<param name="callout.graphics">0</param>
	<param name="paper.type">A4</param>
	<param name="generate.section.toc.level">2</param>
	<param name="use.id.as.filename">1</param>
	<param name="citerefentry.link">1</param>
	<strip-space elements="*"/>
	<template name="generate.citerefentry.link">
		<value-of select="refentrytitle"/>
		<text>.html</text>
	</template>
</stylesheet>
