.class public abstract Landroidx/appcompat/view/menu/y51;
.super Landroidx/coordinatorlayout/widget/CoordinatorLayout$b;
.source "SourceFile"


# instance fields
.field public a:Landroidx/appcompat/view/menu/z51;

.field public b:I

.field public c:I


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Landroidx/coordinatorlayout/widget/CoordinatorLayout$b;-><init>()V

    const/4 v0, 0x0

    iput v0, p0, Landroidx/appcompat/view/menu/y51;->b:I

    iput v0, p0, Landroidx/appcompat/view/menu/y51;->c:I

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .locals 0

    .line 2
    invoke-direct {p0, p1, p2}, Landroidx/coordinatorlayout/widget/CoordinatorLayout$b;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    const/4 p1, 0x0

    iput p1, p0, Landroidx/appcompat/view/menu/y51;->b:I

    iput p1, p0, Landroidx/appcompat/view/menu/y51;->c:I

    return-void
.end method


# virtual methods
.method public E()I
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/y51;->a:Landroidx/appcompat/view/menu/z51;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/z51;->b()I

    move-result v0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    return v0
.end method

.method public F(Landroidx/coordinatorlayout/widget/CoordinatorLayout;Landroid/view/View;I)V
    .locals 0

    invoke-virtual {p1, p2, p3}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->G(Landroid/view/View;I)V

    return-void
.end method

.method public l(Landroidx/coordinatorlayout/widget/CoordinatorLayout;Landroid/view/View;I)Z
    .locals 0

    invoke-virtual {p0, p1, p2, p3}, Landroidx/appcompat/view/menu/y51;->F(Landroidx/coordinatorlayout/widget/CoordinatorLayout;Landroid/view/View;I)V

    iget-object p1, p0, Landroidx/appcompat/view/menu/y51;->a:Landroidx/appcompat/view/menu/z51;

    if-nez p1, :cond_0

    new-instance p1, Landroidx/appcompat/view/menu/z51;

    invoke-direct {p1, p2}, Landroidx/appcompat/view/menu/z51;-><init>(Landroid/view/View;)V

    iput-object p1, p0, Landroidx/appcompat/view/menu/y51;->a:Landroidx/appcompat/view/menu/z51;

    :cond_0
    iget-object p1, p0, Landroidx/appcompat/view/menu/y51;->a:Landroidx/appcompat/view/menu/z51;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/z51;->c()V

    iget-object p1, p0, Landroidx/appcompat/view/menu/y51;->a:Landroidx/appcompat/view/menu/z51;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/z51;->a()V

    iget p1, p0, Landroidx/appcompat/view/menu/y51;->b:I

    const/4 p2, 0x0

    if-eqz p1, :cond_1

    iget-object p3, p0, Landroidx/appcompat/view/menu/y51;->a:Landroidx/appcompat/view/menu/z51;

    invoke-virtual {p3, p1}, Landroidx/appcompat/view/menu/z51;->e(I)Z

    iput p2, p0, Landroidx/appcompat/view/menu/y51;->b:I

    :cond_1
    iget p1, p0, Landroidx/appcompat/view/menu/y51;->c:I

    if-eqz p1, :cond_2

    iget-object p3, p0, Landroidx/appcompat/view/menu/y51;->a:Landroidx/appcompat/view/menu/z51;

    invoke-virtual {p3, p1}, Landroidx/appcompat/view/menu/z51;->d(I)Z

    iput p2, p0, Landroidx/appcompat/view/menu/y51;->c:I

    :cond_2
    const/4 p1, 0x1

    return p1
.end method
