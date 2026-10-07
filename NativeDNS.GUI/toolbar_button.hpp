#pragma once
#include <QStyleOptionToolButton>
#include <QStylePainter>
#include <QToolButton>

class ToolbarButton final : public QToolButton {
public:
    using QToolButton::QToolButton;

protected:
    void paintEvent(QPaintEvent*) override {
        QStyleOptionToolButton option;
        initStyleOption(&option);
        QStylePainter painter(this);
        auto background = option;
        background.icon = {};
        background.text.clear();
        painter.drawComplexControl(QStyle::CC_ToolButton, background);

        // Center the icon above the lower caption without shifting the caption baseline.
        auto icon = option;
        icon.rect.translate(0, -5);
        icon.text.clear();
        icon.toolButtonStyle = Qt::ToolButtonIconOnly;
        painter.drawControl(QStyle::CE_ToolButtonLabel, icon);

        auto caption = option;
        caption.icon = {};
        caption.toolButtonStyle = Qt::ToolButtonTextOnly;
        caption.rect.adjust(4, 0, -4, -11);
        caption.rect.setTop(caption.rect.bottom() - option.fontMetrics.height() + 1);
        painter.drawControl(QStyle::CE_ToolButtonLabel, caption);
    }
};
