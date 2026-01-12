.class public Lcom/google/firebase/analytics/connector/internal/AnalyticsConnectorRegistrar;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Lcom/google/firebase/components/ComponentRegistrar;


# annotations
.annotation build Landroidx/annotation/Keep;
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static synthetic lambda$getComponents$0(Landroidx/appcompat/view/menu/wd;)Landroidx/appcompat/view/menu/z1;
    .locals 3

    const-class v0, Landroidx/appcompat/view/menu/sr;

    invoke-interface {p0, v0}, Landroidx/appcompat/view/menu/wd;->a(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/sr;

    const-class v1, Landroid/content/Context;

    invoke-interface {p0, v1}, Landroidx/appcompat/view/menu/wd;->a(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroid/content/Context;

    const-class v2, Landroidx/appcompat/view/menu/xx0;

    invoke-interface {p0, v2}, Landroidx/appcompat/view/menu/wd;->a(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Landroidx/appcompat/view/menu/xx0;

    invoke-static {v0, v1, p0}, Landroidx/appcompat/view/menu/a2;->c(Landroidx/appcompat/view/menu/sr;Landroid/content/Context;Landroidx/appcompat/view/menu/xx0;)Landroidx/appcompat/view/menu/z1;

    move-result-object p0

    return-object p0
.end method


# virtual methods
.method public getComponents()Ljava/util/List;
    .locals 3
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "MissingPermission"
        }
    .end annotation

    .annotation build Landroidx/annotation/Keep;
    .end annotation

    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Landroidx/appcompat/view/menu/td;",
            ">;"
        }
    .end annotation

    const-class v0, Landroidx/appcompat/view/menu/z1;

    invoke-static {v0}, Landroidx/appcompat/view/menu/td;->e(Ljava/lang/Class;)Landroidx/appcompat/view/menu/td$b;

    move-result-object v0

    const-class v1, Landroidx/appcompat/view/menu/sr;

    invoke-static {v1}, Landroidx/appcompat/view/menu/hl;->j(Ljava/lang/Class;)Landroidx/appcompat/view/menu/hl;

    move-result-object v1

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/td$b;->b(Landroidx/appcompat/view/menu/hl;)Landroidx/appcompat/view/menu/td$b;

    move-result-object v0

    const-class v1, Landroid/content/Context;

    invoke-static {v1}, Landroidx/appcompat/view/menu/hl;->j(Ljava/lang/Class;)Landroidx/appcompat/view/menu/hl;

    move-result-object v1

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/td$b;->b(Landroidx/appcompat/view/menu/hl;)Landroidx/appcompat/view/menu/td$b;

    move-result-object v0

    const-class v1, Landroidx/appcompat/view/menu/xx0;

    invoke-static {v1}, Landroidx/appcompat/view/menu/hl;->j(Ljava/lang/Class;)Landroidx/appcompat/view/menu/hl;

    move-result-object v1

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/td$b;->b(Landroidx/appcompat/view/menu/hl;)Landroidx/appcompat/view/menu/td$b;

    move-result-object v0

    sget-object v1, Landroidx/appcompat/view/menu/ck1;->a:Landroidx/appcompat/view/menu/ck1;

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/td$b;->f(Landroidx/appcompat/view/menu/ce;)Landroidx/appcompat/view/menu/td$b;

    move-result-object v0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/td$b;->e()Landroidx/appcompat/view/menu/td$b;

    move-result-object v0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/td$b;->d()Landroidx/appcompat/view/menu/td;

    move-result-object v0

    const-string v1, "fire-analytics"

    const-string v2, "21.5.0"

    invoke-static {v1, v2}, Landroidx/appcompat/view/menu/s80;->b(Ljava/lang/String;Ljava/lang/String;)Landroidx/appcompat/view/menu/td;

    move-result-object v1

    filled-new-array {v0, v1}, [Landroidx/appcompat/view/menu/td;

    move-result-object v0

    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    return-object v0
.end method
