.class public Landroidx/appcompat/view/menu/w70;
.super Ljava/lang/Object;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroidx/appcompat/view/menu/w70$b;
    }
.end annotation


# instance fields
.field public final a:Landroidx/appcompat/view/menu/hd0;

.field public b:Landroidx/appcompat/view/menu/w70$b;

.field public final c:Landroidx/appcompat/view/menu/hd0$c;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/h8;)V
    .locals 4

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Landroidx/appcompat/view/menu/w70$a;

    invoke-direct {v0, p0}, Landroidx/appcompat/view/menu/w70$a;-><init>(Landroidx/appcompat/view/menu/w70;)V

    iput-object v0, p0, Landroidx/appcompat/view/menu/w70;->c:Landroidx/appcompat/view/menu/hd0$c;

    new-instance v1, Landroidx/appcompat/view/menu/hd0;

    const-string v2, "flutter/keyboard"

    sget-object v3, Landroidx/appcompat/view/menu/mw0;->b:Landroidx/appcompat/view/menu/mw0;

    invoke-direct {v1, p1, v2, v3}, Landroidx/appcompat/view/menu/hd0;-><init>(Landroidx/appcompat/view/menu/h8;Ljava/lang/String;Landroidx/appcompat/view/menu/id0;)V

    iput-object v1, p0, Landroidx/appcompat/view/menu/w70;->a:Landroidx/appcompat/view/menu/hd0;

    invoke-virtual {v1, v0}, Landroidx/appcompat/view/menu/hd0;->e(Landroidx/appcompat/view/menu/hd0$c;)V

    return-void
.end method

.method public static synthetic a(Landroidx/appcompat/view/menu/w70;)Landroidx/appcompat/view/menu/w70$b;
    .locals 0

    iget-object p0, p0, Landroidx/appcompat/view/menu/w70;->b:Landroidx/appcompat/view/menu/w70$b;

    return-object p0
.end method


# virtual methods
.method public b(Landroidx/appcompat/view/menu/w70$b;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/w70;->b:Landroidx/appcompat/view/menu/w70$b;

    return-void
.end method
