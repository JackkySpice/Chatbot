.class public final Landroidx/appcompat/view/menu/bd1;
.super Landroidx/appcompat/view/menu/pc1;
.source "SourceFile"


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/h90;Landroidx/appcompat/view/menu/xy0;)V
    .locals 0

    const/4 p1, 0x4

    invoke-direct {p0, p1, p2}, Landroidx/appcompat/view/menu/pc1;-><init>(ILandroidx/appcompat/view/menu/xy0;)V

    return-void
.end method


# virtual methods
.method public final bridge synthetic d(Landroidx/appcompat/view/menu/cb1;Z)V
    .locals 0

    return-void
.end method

.method public final f(Landroidx/appcompat/view/menu/pb1;)Z
    .locals 1

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/pb1;->w()Ljava/util/Map;

    move-result-object p1

    const/4 v0, 0x0

    invoke-interface {p1, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    invoke-static {p1}, Landroidx/appcompat/view/menu/fy0;->a(Ljava/lang/Object;)V

    const/4 p1, 0x0

    return p1
.end method

.method public final g(Landroidx/appcompat/view/menu/pb1;)[Landroidx/appcompat/view/menu/lr;
    .locals 1

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/pb1;->w()Ljava/util/Map;

    move-result-object p1

    const/4 v0, 0x0

    invoke-interface {p1, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    invoke-static {p1}, Landroidx/appcompat/view/menu/fy0;->a(Ljava/lang/Object;)V

    return-object v0
.end method

.method public final h(Landroidx/appcompat/view/menu/pb1;)V
    .locals 1

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/pb1;->w()Ljava/util/Map;

    move-result-object p1

    const/4 v0, 0x0

    invoke-interface {p1, v0}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    invoke-static {p1}, Landroidx/appcompat/view/menu/fy0;->a(Ljava/lang/Object;)V

    iget-object p1, p0, Landroidx/appcompat/view/menu/pc1;->b:Landroidx/appcompat/view/menu/xy0;

    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-virtual {p1, v0}, Landroidx/appcompat/view/menu/xy0;->e(Ljava/lang/Object;)Z

    return-void
.end method
