#include "action_icons.hpp"
#include <QPainter>
#include <QPainterPath>
#include <QPixmap>
#include <QPolygonF>

namespace {
struct Colors {
    QColor line;
    QColor blue;
    QColor green;
    QColor paper;
};

void line(QPainter& painter, const QColor& color, qreal width) {
    painter.setPen(QPen(color, width, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    painter.setBrush(Qt::NoBrush);
}

void drawServers(QPainter& painter, const Colors& colors) {
    line(painter, colors.line, 2.2);
    painter.drawLine(QPointF(9.5, 11.5), QPointF(23, 10));
    painter.drawLine(QPointF(10, 13), QPointF(17, 24));
    painter.drawLine(QPointF(23, 12), QPointF(18, 23));
    painter.setPen(QPen(colors.paper, 1.2));
    painter.setBrush(colors.blue);
    painter.drawEllipse(QPointF(8.5, 11.5), 5, 5);
    painter.setBrush(colors.green);
    painter.drawEllipse(QPointF(24, 9.5), 4.5, 4.5);
    painter.setBrush(colors.blue);
    painter.drawEllipse(QPointF(18, 25), 5.5, 5.5);
}

void drawRules(QPainter& painter, const Colors& colors) {
    line(painter, colors.line, 1.8);
    painter.setBrush(colors.paper);
    painter.drawRoundedRect(QRectF(7, 6, 20, 24), 2, 2);
    painter.setPen(QPen(colors.blue, 1.7, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    painter.setBrush(colors.paper);
    painter.drawRoundedRect(QRectF(12, 3, 10, 6), 1.5, 1.5);
    line(painter, colors.green, 2);
    for (const qreal y : {15.0, 21.0, 27.0}) {
        painter.drawLine(QPointF(10.5, y), QPointF(12.2, y + 1.5));
        painter.drawLine(QPointF(12.2, y + 1.5), QPointF(14.5, y - 1.5));
    }
    line(painter, colors.line, 1.6);
    for (const qreal y : {15.0, 21.0, 27.0})
        painter.drawLine(QPointF(18, y), QPointF(24, y));
}

void drawClear(QPainter& painter, const Colors& colors) {
    line(painter, colors.line, 1.8);
    painter.setBrush(colors.paper);
    painter.drawRoundedRect(QRectF(5.5, 4, 21, 25), 2, 2);
    line(painter, colors.line, 1.6);
    painter.drawLine(QPointF(9, 10), QPointF(22, 10));
    painter.drawLine(QPointF(9, 15), QPointF(22, 15));
    painter.drawLine(QPointF(9, 20), QPointF(17, 20));
    painter.setPen(QPen(colors.paper, 1.2, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    painter.setBrush(colors.blue);
    painter.drawPolygon(
        QPolygonF{QPointF(18, 23), QPointF(23, 18), QPointF(30, 25), QPointF(25, 30)});
    line(painter, colors.paper, 1.5);
    painter.drawLine(QPointF(21, 26), QPointF(26, 21));
    line(painter, colors.green, 1.8);
    painter.drawLine(QPointF(8, 27), QPointF(11, 27));
}

void drawRestart(QPainter& painter, const Colors& colors) {
    line(painter, colors.blue, 3);
    QPainterPath arc;
    arc.arcMoveTo(QRectF(6, 6, 22, 22), 35);
    arc.arcTo(QRectF(6, 6, 22, 22), 35, 280);
    painter.drawPath(arc);
    painter.setPen(Qt::NoPen);
    painter.setBrush(colors.blue);
    painter.drawPolygon(QPolygonF{QPointF(27.1, 10), QPointF(26.4, 18), QPointF(20, 13.3)});
    line(painter, colors.green, 2.2);
    painter.drawLine(QPointF(12.2, 18), QPointF(16, 22));
    painter.drawLine(QPointF(16, 22), QPointF(22, 13));
}

QPixmap render(ActionIcon icon, const Colors& colors, int size) {
    QPixmap pixmap(size, size);
    pixmap.fill(Qt::transparent);
    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing);
    painter.scale(size / 34.0, size / 34.0);
    switch (icon) {
        case ActionIcon::dns_servers:
            drawServers(painter, colors);
            break;
        case ActionIcon::rules:
            drawRules(painter, colors);
            break;
        case ActionIcon::clear_display:
            drawClear(painter, colors);
            break;
        case ActionIcon::restart:
            drawRestart(painter, colors);
            break;
    }
    return pixmap;
}
} // namespace

QIcon makeActionIcon(ActionIcon icon, bool dark) {
    const Colors colors =
        dark ? Colors{QColor("#e2eaf2"), QColor("#70bdff"), QColor("#69dc91"), QColor("#313a43")}
             : Colors{QColor("#435466"), QColor("#176fb6"), QColor("#278d58"), QColor("#ffffff")};
    const Colors selected{
        QColor("#ffffff"), QColor("#e6f4ff"), QColor("#b8f4cb"), QColor("#0078d7")};
    QIcon result;
    for (const int size : {16, 24, 32, 48, 64}) {
        result.addPixmap(render(icon, colors, size));
        result.addPixmap(render(icon, selected, size), QIcon::Selected);
    }
    return result;
}
