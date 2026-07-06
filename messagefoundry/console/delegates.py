# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Custom item delegates for the console tables.

Presentation only — a delegate paints over a cell but never changes its data, so the underlying
item text is preserved (sorting, selection, and tests that read ``item.text()`` are unaffected)."""

from __future__ import annotations

from PySide6.QtCore import QModelIndex, QPersistentModelIndex, QRectF, QSize, Qt
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import (
    QStyle,
    QStyledItemDelegate,
    QStyleOptionViewItem,
)

from messagefoundry.console import theme

# Qt's item-view callbacks accept either index flavour; match the stub signature exactly.
_Index = QModelIndex | QPersistentModelIndex


class StatusBadgeDelegate(QStyledItemDelegate):
    """Paints a connection's Status cell as a rounded "pill" badge (green running / red stopped or
    failed / amber degraded or simulated). Colours come from the live theme tokens, so a badge
    recolours with an OS light/dark switch on the next repaint."""

    _H_MARGIN = 8  # gap from the cell's left edge to the pill
    _PAD_X = 10  # horizontal padding inside the pill

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index: _Index) -> None:
        tokens = theme.active_tokens()
        bg, fg, label = theme.badge_palette(
            str(index.data(Qt.ItemDataRole.DisplayRole) or ""), tokens
        )

        painter.save()
        # Fill the cell background ourselves (we don't chain to super().paint) so the Status column
        # still matches the table's selection / alternating-row striping behind the pill.
        if option.state & QStyle.StateFlag.State_Selected:
            painter.fillRect(option.rect, QColor(tokens.selection_bg))
        elif option.features & QStyleOptionViewItem.ViewItemFeature.Alternate:
            painter.fillRect(option.rect, QColor(tokens.bg_elevated))
        else:
            painter.fillRect(option.rect, QColor(tokens.bg_surface))

        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        metrics = painter.fontMetrics()
        text_w = metrics.horizontalAdvance(label)
        pill_h = float(metrics.height() + 6)
        pill_w = float(text_w + self._PAD_X * 2)
        x = float(option.rect.left() + self._H_MARGIN)
        y = option.rect.center().y() - pill_h / 2 + 0.5
        pill = QRectF(x, y, pill_w, pill_h)

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(bg))
        radius = pill_h / 2
        painter.drawRoundedRect(pill, radius, radius)
        painter.setPen(QColor(fg))
        painter.drawText(pill, int(Qt.AlignmentFlag.AlignCenter), label)
        painter.restore()

    def sizeHint(self, option: QStyleOptionViewItem, index: _Index) -> QSize:
        # Reserve enough width for the pill (text + padding + margin) so autosizing the column to
        # contents doesn't clip the badge, and give rows a little vertical room.
        base = super().sizeHint(option, index)
        return QSize(base.width() + self._PAD_X * 2 + self._H_MARGIN * 2, max(base.height(), 30))
