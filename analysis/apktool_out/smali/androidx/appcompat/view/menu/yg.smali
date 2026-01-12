.class public abstract Landroidx/appcompat/view/menu/yg;
.super Landroidx/appcompat/view/menu/x7;
.source "SourceFile"


# instance fields
.field public final n:Landroidx/appcompat/view/menu/jh;

.field public transient o:Landroidx/appcompat/view/menu/wg;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/wg;)V
    .locals 1

    if-eqz p1, :cond_0

    .line 2
    invoke-interface {p1}, Landroidx/appcompat/view/menu/wg;->b()Landroidx/appcompat/view/menu/jh;

    move-result-object v0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    invoke-direct {p0, p1, v0}, Landroidx/appcompat/view/menu/yg;-><init>(Landroidx/appcompat/view/menu/wg;Landroidx/appcompat/view/menu/jh;)V

    return-void
.end method

.method public constructor <init>(Landroidx/appcompat/view/menu/wg;Landroidx/appcompat/view/menu/jh;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Landroidx/appcompat/view/menu/x7;-><init>(Landroidx/appcompat/view/menu/wg;)V

    iput-object p2, p0, Landroidx/appcompat/view/menu/yg;->n:Landroidx/appcompat/view/menu/jh;

    return-void
.end method


# virtual methods
.method public b()Landroidx/appcompat/view/menu/jh;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/yg;->n:Landroidx/appcompat/view/menu/jh;

    invoke-static {v0}, Landroidx/appcompat/view/menu/x50;->b(Ljava/lang/Object;)V

    return-object v0
.end method

.method public l()V
    .locals 3

    iget-object v0, p0, Landroidx/appcompat/view/menu/yg;->o:Landroidx/appcompat/view/menu/wg;

    if-eqz v0, :cond_0

    if-eq v0, p0, :cond_0

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/yg;->b()Landroidx/appcompat/view/menu/jh;

    move-result-object v1

    sget-object v2, Landroidx/appcompat/view/menu/zg;->b:Landroidx/appcompat/view/menu/zg$b;

    invoke-interface {v1, v2}, Landroidx/appcompat/view/menu/jh;->d(Landroidx/appcompat/view/menu/jh$c;)Landroidx/appcompat/view/menu/jh$b;

    move-result-object v1

    invoke-static {v1}, Landroidx/appcompat/view/menu/x50;->b(Ljava/lang/Object;)V

    check-cast v1, Landroidx/appcompat/view/menu/zg;

    invoke-interface {v1, v0}, Landroidx/appcompat/view/menu/zg;->x(Landroidx/appcompat/view/menu/wg;)V

    :cond_0
    sget-object v0, Landroidx/appcompat/view/menu/ld;->m:Landroidx/appcompat/view/menu/ld;

    iput-object v0, p0, Landroidx/appcompat/view/menu/yg;->o:Landroidx/appcompat/view/menu/wg;

    return-void
.end method

.method public final m()Landroidx/appcompat/view/menu/wg;
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/yg;->o:Landroidx/appcompat/view/menu/wg;

    if-nez v0, :cond_2

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/yg;->b()Landroidx/appcompat/view/menu/jh;

    move-result-object v0

    sget-object v1, Landroidx/appcompat/view/menu/zg;->b:Landroidx/appcompat/view/menu/zg$b;

    invoke-interface {v0, v1}, Landroidx/appcompat/view/menu/jh;->d(Landroidx/appcompat/view/menu/jh$c;)Landroidx/appcompat/view/menu/jh$b;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/zg;

    if-eqz v0, :cond_0

    invoke-interface {v0, p0}, Landroidx/appcompat/view/menu/zg;->z(Landroidx/appcompat/view/menu/wg;)Landroidx/appcompat/view/menu/wg;

    move-result-object v0

    if-nez v0, :cond_1

    :cond_0
    move-object v0, p0

    :cond_1
    iput-object v0, p0, Landroidx/appcompat/view/menu/yg;->o:Landroidx/appcompat/view/menu/wg;

    :cond_2
    return-object v0
.end method
