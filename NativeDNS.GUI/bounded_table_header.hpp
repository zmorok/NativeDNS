#pragma once
#include <QHeaderView>
#include <QMouseEvent>
#include <QResizeEvent>
#include <QStyle>
#include <QTableView>
#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <numeric>
#include <vector>

class BoundedTableHeader final : public QHeaderView {
public:
    BoundedTableHeader(
        QTableView* table, std::vector<int> minimums, int first, int second, int fixedFrom)
        : QHeaderView(Qt::Horizontal, table), minimums_(std::move(minimums)),
          fixedFrom_(fixedFrom) {
        table->setHorizontalHeader(this);
        setStretchLastSection(false);
        setCascadingSectionResizes(false);
        setMinimumSectionSize(1);
        for (int column = 0; column < count(); ++column) {
            const auto label = model()->headerData(column, Qt::Horizontal).toString();
            minimums_[column] =
                std::max(minimums_[column], fontMetrics().horizontalAdvance(label) + 24);
            if (column >= fixedFrom_)
                minimums_[column] = std::max(minimums_[column], defaultSectionSize());
            // The right edge of the last flexible column is anchored to the table.
            // Its width is still adjustable by dragging the divider on its left.
            setSectionResizeMode(column, column >= fixedFrom_ - 1 ? Fixed : Interactive);
            widths_.push_back(std::max(minimums_[column], defaultSectionSize()));
        }
        widths_[first] += defaultSectionSize();
        widths_[second] += defaultSectionSize();
        const int rowHeader = std::max(table->verticalHeader()->sizeHint().width(),
                                       fontMetrics().horizontalAdvance("4096") + 12);
        table->setMinimumWidth(std::accumulate(minimums_.begin(), minimums_.end(), 0) + rowHeader +
                               2 * table->frameWidth() +
                               style()->pixelMetric(QStyle::PM_ScrollBarExtent));
        table->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        connect(this, &QHeaderView::sectionResized, this, [this](int column, int, int requested) {
            if (adjusting_)
                return;
            if (column >= 0 && column + 1 < fixedFrom_) {
                const int neighbor = column + 1;
                const int delta = std::clamp(requested - widths_[column],
                                             minimums_[column] - widths_[column],
                                             widths_[neighbor] - minimums_[neighbor]);
                widths_[column] += delta;
                widths_[neighbor] -= delta;
            }
            applyWidths();
        });
        fitToViewport();
    }

protected:
    void mousePressEvent(QMouseEvent* event) override {
        if (event->button() == Qt::LeftButton) {
            const int x = static_cast<int>(event->position().x());
            const int grip = style()->pixelMetric(QStyle::PM_HeaderGripMargin);
            for (int column = 0; column + 1 < fixedFrom_; ++column) {
                const int edge = sectionViewportPosition(column) + sectionSize(column);
                if (std::abs(x - edge) <= grip) {
                    dragColumn_ = column;
                    dragStart_ = x;
                    dragLeftWidth_ = widths_[column];
                    dragRightWidth_ = widths_[column + 1];
                    event->accept();
                    return;
                }
            }
        }
        QHeaderView::mousePressEvent(event);
    }
    void mouseMoveEvent(QMouseEvent* event) override {
        if (dragColumn_ >= 0) {
            const int delta = std::clamp(static_cast<int>(event->position().x()) - dragStart_,
                                         minimums_[dragColumn_] - dragLeftWidth_,
                                         dragRightWidth_ - minimums_[dragColumn_ + 1]);
            widths_[dragColumn_] = dragLeftWidth_ + delta;
            widths_[dragColumn_ + 1] = dragRightWidth_ - delta;
            applyWidths();
            event->accept();
            return;
        }
        QHeaderView::mouseMoveEvent(event);
    }
    void mouseReleaseEvent(QMouseEvent* event) override {
        if (dragColumn_ >= 0 && event->button() == Qt::LeftButton) {
            dragColumn_ = -1;
            event->accept();
            return;
        }
        QHeaderView::mouseReleaseEvent(event);
    }
    void resizeEvent(QResizeEvent* event) override {
        dragColumn_ = -1;
        QHeaderView::resizeEvent(event);
        fitToViewport();
    }

private:
    void applyWidths() {
        adjusting_ = true;
        for (int column = 0; column < count(); ++column)
            resizeSection(column, widths_[column]);
        adjusting_ = false;
    }
    void fitToViewport() {
        if (adjusting_ || widths_.size() != minimums_.size() ||
            widths_.size() != static_cast<size_t>(count()))
            return;
        const int minimum = std::accumulate(minimums_.begin(), minimums_.end(), 0);
        if (viewport()->width() < minimum)
            return;
        const int available = std::max(0, viewport()->width() - minimum);
        int weight = 0;
        for (int column = 0; column < fixedFrom_; ++column)
            weight += widths_[column] - minimums_[column];
        int remaining = available;
        for (int column = 0; column < fixedFrom_; ++column) {
            const int extra = column + 1 == fixedFrom_ ? remaining
                              : weight
                                  ? static_cast<int>(static_cast<int64_t>(available) *
                                                     (widths_[column] - minimums_[column]) / weight)
                                  : available / fixedFrom_;
            widths_[column] = minimums_[column] + extra;
            remaining -= extra;
        }
        applyWidths();
    }
    std::vector<int> minimums_, widths_;
    int fixedFrom_;
    int dragColumn_ = -1, dragStart_ = 0, dragLeftWidth_ = 0, dragRightWidth_ = 0;
    bool adjusting_ = false;
};
