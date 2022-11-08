/*
 * Copyright (C) 2019 Michael Clarke
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */
package com.github.mc1arke.sonarqube.plugin.ce.pullrequest.markup;

import java.util.stream.IntStream;
import static com.google.common.html.HtmlEscapers.htmlEscaper;

public final class MarkdownFormatterFactory implements FormatterFactory {

    @Override
    public Formatter<Document> documentFormatter() {
        return new BaseFormatter<Document>() {
            @Override
            public String format(Document node, FormatterFactory formatterFactory) {
                return childContents(node, formatterFactory);
            }
        };
    }

    @Override
    public Formatter<Heading> headingFormatter() {
        return new BaseFormatter<Heading>() {
            @Override
            public String format(Heading node, FormatterFactory formatterFactory) {
                StringBuilder output = new StringBuilder();
                IntStream.range(0, node.getLevel()).forEach(i -> output.append("#"));
                return output.append(" ").append(childContents(node, formatterFactory)).append(System.lineSeparator())
                        .toString();
            }
        };
    }

    @Override
    public Formatter<Image> imageFormatter() {
        return new BaseFormatter<Image>() {
            @Override
            public String format(Image node, FormatterFactory formatterFactory) {
                String imgTag = String.format("![%s](%s)", node.getAltText(), node.getSource());
                if (node.suppressLink()) {
                    imgTag = String.format("<a title=\"%s\">%s</a>", htmlEscaper().escape(node.getAltText()), imgTag);
                }
                return imgTag;
            }
        };
    }

    @Override
    public Formatter<Link> linkFormatter() {
        return new BaseFormatter<Link>() {
            @Override
            public String format(Link node, FormatterFactory formatterFactory) {
                return String.format("[%s](%s)", node.getChildren().isEmpty() ? node.getUrl() : childContents(node, formatterFactory), node.getUrl());
            }
        };
    }

    @Override
    public Formatter<List> listFormatter() {
        return new BaseFormatter<List>() {
            @Override
            public String format(List node, FormatterFactory formatterFactory) {
                // check valid list style
                if (node.getStyle() != List.Style.BULLET && node.getStyle() != List.Style.NONE) {
                    throw new IllegalArgumentException("Unknown list type: " + node.getStyle());
                }
                StringBuilder output = new StringBuilder();
                node.getChildren().forEach(i -> {
                    // "bullet" needs a prefix
                    if (node.getStyle() == List.Style.BULLET) {
                        output.append("- ");
                    }
                    // output actual item
                    output.append(listItemFormatter().format((ListItem) i, formatterFactory));
                    // "none" needs a double trailing slash to force a visual linebreak
                    if (node.getStyle() == List.Style.NONE) {
                        output.append("  ");
                    }
                    output.append(System.lineSeparator());
                });
                output.append(System.lineSeparator());
                return output.toString();
            }
        };
    }

    @Override
    public Formatter<ListItem> listItemFormatter() {
        return new BaseFormatter<ListItem>() {
            @Override
            public String format(ListItem node, FormatterFactory formatterFactory) {
                return childContents(node, formatterFactory);
            }
        };
    }

    @Override
    public Formatter<Paragraph> paragraphFormatter() {
        return new BaseFormatter<Paragraph>() {
            @Override
            public String format(Paragraph node, FormatterFactory formatterFactory) {
                return childContents(node, formatterFactory) + System.lineSeparator() + System.lineSeparator();
            }
        };
    }

    @Override
    public Formatter<Text> textFormatter() {
        return new BaseFormatter<Text>() {
            @Override
            public String format(Text node, FormatterFactory formatterFactory) {
                String formattedText = htmlEscaper().escape(node.getContent());
                if (!node.allowLeadingTrailingWhitespace()) {
                    formattedText = formattedText.trim();
                }
                return formattedText;
            }
        };
    }
}
