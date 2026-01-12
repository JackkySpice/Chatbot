.class public Landroidx/appcompat/view/menu/t10$e;
.super Landroidx/appcompat/view/menu/jd0;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/t10;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "e"
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Landroidx/appcompat/view/menu/jd0;-><init>()V

    return-void
.end method


# virtual methods
.method public d(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    invoke-static {}, Landroidx/appcompat/view/menu/jv0;->l()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-static {}, Landroidx/appcompat/view/menu/jv0;->f()Landroidx/appcompat/view/menu/jv0;

    move-result-object p1

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result p2

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->E2()Ljava/lang/String;

    move-result-object p3

    invoke-virtual {p1, p2, p3}, Landroidx/appcompat/view/menu/jv0;->i(ILjava/lang/String;)Landroidx/appcompat/view/menu/o6;

    move-result-object p1

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/o6;->b()Landroid/location/Location;

    move-result-object p1

    return-object p1

    :cond_0
    invoke-virtual {p2, p1, p3}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
