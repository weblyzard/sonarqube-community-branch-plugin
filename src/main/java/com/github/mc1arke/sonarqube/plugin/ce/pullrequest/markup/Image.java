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

public final class Image extends Node {

    private final String altText;
    private final String source;
    private final boolean suppressLink;

    public Image(String altText, String source) {
        this(altText, source, false);
    }

    public Image(String altText, String source, boolean suppressLink) {
        super();
        this.altText = altText;
        this.source = source;
        this.suppressLink = suppressLink;
    }

    String getAltText() {
        return altText;
    }

    String getSource() {
        return source;
    }

    boolean suppressLink() {
        return suppressLink;
    }

    @Override
    boolean isValidChild(Node child) {
        return false;
    }
}
