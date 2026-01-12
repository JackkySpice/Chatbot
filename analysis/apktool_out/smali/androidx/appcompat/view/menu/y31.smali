.class public final synthetic Landroidx/appcompat/view/menu/y31;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/ly0$a;


# instance fields
.field public final synthetic a:Landroidx/appcompat/view/menu/e41;

.field public final synthetic b:Landroidx/appcompat/view/menu/z11;


# direct methods
.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/e41;Landroidx/appcompat/view/menu/z11;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/y31;->a:Landroidx/appcompat/view/menu/e41;

    iput-object p2, p0, Landroidx/appcompat/view/menu/y31;->b:Landroidx/appcompat/view/menu/z11;

    return-void
.end method


# virtual methods
.method public final a()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/y31;->a:Landroidx/appcompat/view/menu/e41;

    iget-object v1, p0, Landroidx/appcompat/view/menu/y31;->b:Landroidx/appcompat/view/menu/z11;

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/e41;->d(Landroidx/appcompat/view/menu/e41;Landroidx/appcompat/view/menu/z11;)Ljava/lang/Iterable;

    move-result-object v0

    return-object v0
.end method
