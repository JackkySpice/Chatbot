.class public final Landroidx/appcompat/view/menu/ge2;
.super Landroidx/appcompat/view/menu/cg1;
.source "SourceFile"


# instance fields
.field public final o:Landroidx/appcompat/view/menu/df2;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/df2;)V
    .locals 5

    const-string v0, "internal.logger"

    invoke-direct {p0, v0}, Landroidx/appcompat/view/menu/cg1;-><init>(Ljava/lang/String;)V

    iput-object p1, p0, Landroidx/appcompat/view/menu/ge2;->o:Landroidx/appcompat/view/menu/df2;

    iget-object p1, p0, Landroidx/appcompat/view/menu/cg1;->n:Ljava/util/Map;

    new-instance v0, Landroidx/appcompat/view/menu/xe2;

    const/4 v1, 0x0

    const/4 v2, 0x1

    invoke-direct {v0, p0, v1, v2}, Landroidx/appcompat/view/menu/xe2;-><init>(Landroidx/appcompat/view/menu/ge2;ZZ)V

    const-string v3, "log"

    invoke-interface {p1, v3, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    iget-object p1, p0, Landroidx/appcompat/view/menu/cg1;->n:Ljava/util/Map;

    new-instance v0, Landroidx/appcompat/view/menu/ld2;

    const-string v4, "silent"

    invoke-direct {v0, p0, v4}, Landroidx/appcompat/view/menu/ld2;-><init>(Landroidx/appcompat/view/menu/ge2;Ljava/lang/String;)V

    invoke-interface {p1, v4, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    iget-object p1, p0, Landroidx/appcompat/view/menu/cg1;->n:Ljava/util/Map;

    invoke-interface {p1, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroidx/appcompat/view/menu/cg1;

    new-instance v0, Landroidx/appcompat/view/menu/xe2;

    invoke-direct {v0, p0, v2, v2}, Landroidx/appcompat/view/menu/xe2;-><init>(Landroidx/appcompat/view/menu/ge2;ZZ)V

    invoke-virtual {p1, v3, v0}, Landroidx/appcompat/view/menu/cg1;->n(Ljava/lang/String;Landroidx/appcompat/view/menu/mg1;)V

    iget-object p1, p0, Landroidx/appcompat/view/menu/cg1;->n:Ljava/util/Map;

    new-instance v0, Landroidx/appcompat/view/menu/re2;

    const-string v2, "unmonitored"

    invoke-direct {v0, p0, v2}, Landroidx/appcompat/view/menu/re2;-><init>(Landroidx/appcompat/view/menu/ge2;Ljava/lang/String;)V

    invoke-interface {p1, v2, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    iget-object p1, p0, Landroidx/appcompat/view/menu/cg1;->n:Ljava/util/Map;

    invoke-interface {p1, v2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroidx/appcompat/view/menu/cg1;

    new-instance v0, Landroidx/appcompat/view/menu/xe2;

    invoke-direct {v0, p0, v1, v1}, Landroidx/appcompat/view/menu/xe2;-><init>(Landroidx/appcompat/view/menu/ge2;ZZ)V

    invoke-virtual {p1, v3, v0}, Landroidx/appcompat/view/menu/cg1;->n(Ljava/lang/String;Landroidx/appcompat/view/menu/mg1;)V

    return-void
.end method

.method public static bridge synthetic e(Landroidx/appcompat/view/menu/ge2;)Landroidx/appcompat/view/menu/df2;
    .locals 0

    iget-object p0, p0, Landroidx/appcompat/view/menu/ge2;->o:Landroidx/appcompat/view/menu/df2;

    return-object p0
.end method


# virtual methods
.method public final a(Landroidx/appcompat/view/menu/lw1;Ljava/util/List;)Landroidx/appcompat/view/menu/mg1;
    .locals 0

    sget-object p1, Landroidx/appcompat/view/menu/mg1;->e:Landroidx/appcompat/view/menu/mg1;

    return-object p1
.end method
