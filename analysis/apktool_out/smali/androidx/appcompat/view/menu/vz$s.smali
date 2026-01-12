.class public Landroidx/appcompat/view/menu/vz$s;
.super Landroidx/appcompat/view/menu/jd0;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/vz;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "s"
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

    invoke-static {p3}, Landroidx/appcompat/view/menu/ld0;->h([Ljava/lang/Object;)V

    const/4 p1, 0x0

    aget-object p1, p3, p1

    check-cast p1, Landroid/content/Intent;

    const/4 p2, 0x1

    aget-object p2, p3, p2

    check-cast p2, Ljava/lang/String;

    invoke-static {}, Landroidx/appcompat/view/menu/uu0;->i()Landroidx/appcompat/view/menu/zu0;

    move-result-object p3

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v0

    invoke-virtual {p3, p1, p2, v0}, Landroidx/appcompat/view/menu/zu0;->x(Landroid/content/Intent;Ljava/lang/String;I)Landroid/os/IBinder;

    move-result-object p1

    return-object p1
.end method
