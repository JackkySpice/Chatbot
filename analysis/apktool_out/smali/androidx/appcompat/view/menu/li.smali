.class public abstract Landroidx/appcompat/view/menu/li;
.super Landroidx/appcompat/view/menu/lb0;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroidx/appcompat/view/menu/li$b;,
        Landroidx/appcompat/view/menu/li$c;
    }
.end annotation


# instance fields
.field public y:Landroidx/appcompat/view/menu/li$b;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/li$b;)V
    .locals 0

    .line 2
    invoke-direct {p0, p1}, Landroidx/appcompat/view/menu/lb0;-><init>(Landroidx/appcompat/view/menu/lb0$c;)V

    iput-object p1, p0, Landroidx/appcompat/view/menu/li;->y:Landroidx/appcompat/view/menu/li$b;

    return-void
.end method

.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/li$b;Landroidx/appcompat/view/menu/li$a;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Landroidx/appcompat/view/menu/li;-><init>(Landroidx/appcompat/view/menu/li$b;)V

    return-void
.end method

.method public static synthetic e0(Landroidx/appcompat/view/menu/li$b;)Landroidx/appcompat/view/menu/li;
    .locals 0

    invoke-static {p0}, Landroidx/appcompat/view/menu/li;->f0(Landroidx/appcompat/view/menu/li$b;)Landroidx/appcompat/view/menu/li;

    move-result-object p0

    return-object p0
.end method

.method public static f0(Landroidx/appcompat/view/menu/li$b;)Landroidx/appcompat/view/menu/li;
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/li$c;

    invoke-direct {v0, p0}, Landroidx/appcompat/view/menu/li$c;-><init>(Landroidx/appcompat/view/menu/li$b;)V

    return-object v0
.end method

.method public static g0(Landroidx/appcompat/view/menu/ot0;)Landroidx/appcompat/view/menu/li;
    .locals 3

    new-instance v0, Landroidx/appcompat/view/menu/li$b;

    if-eqz p0, :cond_0

    goto :goto_0

    :cond_0
    new-instance p0, Landroidx/appcompat/view/menu/ot0;

    invoke-direct {p0}, Landroidx/appcompat/view/menu/ot0;-><init>()V

    :goto_0
    new-instance v1, Landroid/graphics/RectF;

    invoke-direct {v1}, Landroid/graphics/RectF;-><init>()V

    const/4 v2, 0x0

    invoke-direct {v0, p0, v1, v2}, Landroidx/appcompat/view/menu/li$b;-><init>(Landroidx/appcompat/view/menu/ot0;Landroid/graphics/RectF;Landroidx/appcompat/view/menu/li$a;)V

    invoke-static {v0}, Landroidx/appcompat/view/menu/li;->f0(Landroidx/appcompat/view/menu/li$b;)Landroidx/appcompat/view/menu/li;

    move-result-object p0

    return-object p0
.end method


# virtual methods
.method public h0()Z
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/li;->y:Landroidx/appcompat/view/menu/li$b;

    invoke-static {v0}, Landroidx/appcompat/view/menu/li$b;->a(Landroidx/appcompat/view/menu/li$b;)Landroid/graphics/RectF;

    move-result-object v0

    invoke-virtual {v0}, Landroid/graphics/RectF;->isEmpty()Z

    move-result v0

    xor-int/lit8 v0, v0, 0x1

    return v0
.end method

.method public i0()V
    .locals 1

    const/4 v0, 0x0

    invoke-virtual {p0, v0, v0, v0, v0}, Landroidx/appcompat/view/menu/li;->j0(FFFF)V

    return-void
.end method

.method public j0(FFFF)V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/li;->y:Landroidx/appcompat/view/menu/li$b;

    invoke-static {v0}, Landroidx/appcompat/view/menu/li$b;->a(Landroidx/appcompat/view/menu/li$b;)Landroid/graphics/RectF;

    move-result-object v0

    iget v0, v0, Landroid/graphics/RectF;->left:F

    cmpl-float v0, p1, v0

    if-nez v0, :cond_0

    iget-object v0, p0, Landroidx/appcompat/view/menu/li;->y:Landroidx/appcompat/view/menu/li$b;

    invoke-static {v0}, Landroidx/appcompat/view/menu/li$b;->a(Landroidx/appcompat/view/menu/li$b;)Landroid/graphics/RectF;

    move-result-object v0

    iget v0, v0, Landroid/graphics/RectF;->top:F

    cmpl-float v0, p2, v0

    if-nez v0, :cond_0

    iget-object v0, p0, Landroidx/appcompat/view/menu/li;->y:Landroidx/appcompat/view/menu/li$b;

    invoke-static {v0}, Landroidx/appcompat/view/menu/li$b;->a(Landroidx/appcompat/view/menu/li$b;)Landroid/graphics/RectF;

    move-result-object v0

    iget v0, v0, Landroid/graphics/RectF;->right:F

    cmpl-float v0, p3, v0

    if-nez v0, :cond_0

    iget-object v0, p0, Landroidx/appcompat/view/menu/li;->y:Landroidx/appcompat/view/menu/li$b;

    invoke-static {v0}, Landroidx/appcompat/view/menu/li$b;->a(Landroidx/appcompat/view/menu/li$b;)Landroid/graphics/RectF;

    move-result-object v0

    iget v0, v0, Landroid/graphics/RectF;->bottom:F

    cmpl-float v0, p4, v0

    if-eqz v0, :cond_1

    :cond_0
    iget-object v0, p0, Landroidx/appcompat/view/menu/li;->y:Landroidx/appcompat/view/menu/li$b;

    invoke-static {v0}, Landroidx/appcompat/view/menu/li$b;->a(Landroidx/appcompat/view/menu/li$b;)Landroid/graphics/RectF;

    move-result-object v0

    invoke-virtual {v0, p1, p2, p3, p4}, Landroid/graphics/RectF;->set(FFFF)V

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/lb0;->invalidateSelf()V

    :cond_1
    return-void
.end method

.method public k0(Landroid/graphics/RectF;)V
    .locals 3

    iget v0, p1, Landroid/graphics/RectF;->left:F

    iget v1, p1, Landroid/graphics/RectF;->top:F

    iget v2, p1, Landroid/graphics/RectF;->right:F

    iget p1, p1, Landroid/graphics/RectF;->bottom:F

    invoke-virtual {p0, v0, v1, v2, p1}, Landroidx/appcompat/view/menu/li;->j0(FFFF)V

    return-void
.end method

.method public mutate()Landroid/graphics/drawable/Drawable;
    .locals 3

    new-instance v0, Landroidx/appcompat/view/menu/li$b;

    iget-object v1, p0, Landroidx/appcompat/view/menu/li;->y:Landroidx/appcompat/view/menu/li$b;

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Landroidx/appcompat/view/menu/li$b;-><init>(Landroidx/appcompat/view/menu/li$b;Landroidx/appcompat/view/menu/li$a;)V

    iput-object v0, p0, Landroidx/appcompat/view/menu/li;->y:Landroidx/appcompat/view/menu/li$b;

    return-object p0
.end method
